/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.net.eap.crypto;

import static com.android.internal.net.eap.EapAuthenticator.LOG;

import android.annotation.IntDef;

import com.android.internal.annotations.VisibleForTesting;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * TlsSession provides the TLS handshake and encryption/decryption functionality for EAP-TTLS.
 *
 * <p>The primary return mechanism of TlsSession is via {@link TlsResult TlsResult}, which contains
 * an outbound message and the status of the operation.
 *
 * <p>The handshake is initiated via the {@link #startHandshake() startHandshake} method which wraps
 * the first outbound message. Any handshake message that follows is then processed via {@link
 * #processHandshakeData(byte[]) processHandshakeData} which will eventually produce a TlsResult.
 *
 * <p>Once a handshake is complete, data can be encrypted via {@link #processOutgoingData(byte[])
 * processOutgoingData} which will produce a TlsResult with the encrypted message. Decryption is
 * similar and is handled via {@link #processIncomingData(byte[]) processIncomingData} which
 * produces a TlsResult with the decrypted application data.
 */
public class TlsSession {
    private static final String TAG = TlsSession.class.getSimpleName();

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        TLS_STATUS_TUNNEL_ESTABLISHED,
        TLS_STATUS_SUCCESS,
        TLS_STATUS_FAILURE,
        TLS_STATUS_CLOSED
    })
    public @interface TlsStatus {}

    public static final int TLS_STATUS_TUNNEL_ESTABLISHED = 0;
    public static final int TLS_STATUS_SUCCESS = 1;
    public static final int TLS_STATUS_FAILURE = 2;
    public static final int TLS_STATUS_CLOSED = 3;

    // TODO(b/163135610): Support for TLS 1.3 in EAP-TTLS
    private static final String[] ENABLED_TLS_PROTOCOLS = {"TLSv1.2"};
    // The trust management algorithm, keystore type and the trust manager provider are equivalent
    // to those used in the IKEv2 library
    private static final String CERT_PATH_ALGO_PKIX = "PKIX";
    private static final String KEY_STORE_TYPE_PKCS12 = "PKCS12";
    private static final Provider TRUST_MANAGER_PROVIDER = Security.getProvider("HarmonyJSSE");

    private final SSLContext mSslContext;
    private final SSLSession mSslSession;
    private final SSLEngine mSslEngine;
    private final SecureRandom mSecureRandom;

    // this is kept as an outer variable as the finished state is returned exclusively by
    // wrap/unwrap so it is important to keep track of the handshake status separately
    @VisibleForTesting HandshakeStatus mHandshakeStatus;
    private TrustManager[] mTrustManagers;

    // Package-private
    TlsSession(X509Certificate trustedCa, SecureRandom secureRandom)
            throws GeneralSecurityException, IOException {
        mSecureRandom = secureRandom;
        initTrustManagers(trustedCa);
        mSslContext = SSLContext.getInstance("TLSv1.2");
        mSslContext.init(null, mTrustManagers, secureRandom);
        mSslEngine = mSslContext.createSSLEngine();
        mSslEngine.setEnabledProtocols(ENABLED_TLS_PROTOCOLS);
        mSslEngine.setUseClientMode(true);
        mSslSession = mSslEngine.getSession();
    }

    @VisibleForTesting
    TlsSession(
            SSLContext sslContext,
            SSLEngine sslEngine,
            SSLSession sslSession,
            SecureRandom secureRandom) {
        mSslContext = sslContext;
        mSslEngine = sslEngine;
        mSecureRandom = secureRandom;
        mSslSession = sslSession;
    }

    /**
     * Creates the trust manager instance needed to instantiate the SSLContext
     *
     * @param trustedCa a specific CA to trust or null if the system-default is preferred
     * @throws GeneralSecurityException if the trust manager cannot be initialized
     * @throws IOException if there is an I/O issue with keystore data
     */
    private void initTrustManagers(X509Certificate trustedCa)
            throws GeneralSecurityException, IOException {
        // TODO(b/160798904): Pass TrustManager through EAP authenticator in EAP-TTLS

        KeyStore keyStore = null;

        if (trustedCa != null) {
            keyStore = KeyStore.getInstance(KEY_STORE_TYPE_PKCS12);
            keyStore.load(null);
            String alias = trustedCa.getSubjectX500Principal().getName() + trustedCa.hashCode();
            keyStore.setCertificateEntry(alias, trustedCa);
        }

        TrustManagerFactory tmFactory =
                TrustManagerFactory.getInstance(CERT_PATH_ALGO_PKIX, TRUST_MANAGER_PROVIDER);
        tmFactory.init(keyStore);

        mTrustManagers = tmFactory.getTrustManagers();
        for (TrustManager tm : mTrustManagers) {
            if (tm instanceof X509TrustManager) {
                return;
            }
        }

        throw new ProviderException(
                "X509TrustManager is not supported by provider " + TRUST_MANAGER_PROVIDER);
    }

    /**
     * Initializes the TLS handshake by wrapping the first ClientHello message
     *
     * <p>Note that no handshaking occurred during the writing of this code. The underlying
     * implementation of handshake used here is the elbow bump.
     *
     * @return a tls result containing outbound data the and status of operation
     */
    public TlsResult startHandshake() {
        // TODO(b/163561894): Revert to persistent ByteBuffers in TLS Session
        ByteBuffer applicationData = ByteBuffer.allocate(mSslSession.getApplicationBufferSize());
        ByteBuffer packetData = ByteBuffer.allocate(mSslSession.getPacketBufferSize());

        SSLEngineResult result;
        try {
            // A wrap implicitly begins the handshake. This will produce the ClientHello
            // message.
            result = mSslEngine.wrap(applicationData, packetData);
        } catch (SSLException e) {
            LOG.e(TAG, "Failed to initiate handshake", e);
            return new TlsResult(TLS_STATUS_FAILURE);
        }
        mHandshakeStatus = result.getHandshakeStatus();

        return new TlsResult(getByteArrayFromBuffer(packetData), TLS_STATUS_SUCCESS);
    }

    /**
     * Processes an incoming handshake message and updates the handshake status accordingly
     *
     * <p>Note that Conscrypt's SSLEngine only returns FINISHED once. In TLS 1.2, this is returned
     * after a wrap call. However, this wrap occurs AFTER the handshake is complete on both the
     * server and client side. As a result, the wrap would simply encrypt the entire buffer (of
     * zeroes) and produce garbage data. Instead, an EAP-identity within an EAP-MESSAGE AVP is
     * passed and encrypted as this is the first message sent after the handshake. If the EAP
     * identity is not passed and the garbage data packet is simply dropped, all subsequent packets
     * will have incorrect sequence numbers and fail message authentication.
     *
     * <p>The AVP, which contains an EAP-identity response, can safely be passed for each
     * wrap/unwrap as it is ignored if the handshake is still in progress. Consumption and
     * production during the handshake occur within the packet buffers.
     *
     * <p>Note that due to the ongoing COVID-19 pandemic, increased sanitization measures are being
     * employed in-between processHandshakeData calls in order to keep the buffers clean (RFC-EB)
     *
     * @param handshakeData the message to process
     * @param avp an avp containing an EAP-identity response
     * @return a {@link TlsResult} containing an outbound message and status of operation
     */
    public TlsResult processHandshakeData(byte[] handshakeData, byte[] avp) {
        // TODO(b/163561894): Revert to persistent ByteBuffers in TLS Session
        ByteBuffer applicationData = ByteBuffer.allocate(mSslSession.getApplicationBufferSize());
        ByteBuffer packetData = ByteBuffer.allocate(mSslSession.getPacketBufferSize());

        try {
            // The application buffer size is guaranteed to be larger than that of the AVP as the
            // handshaking messages contain substantially more data
            applicationData.put(avp);
            packetData.put(handshakeData);
        } catch (BufferOverflowException e) {
            // The connection will be closed because the buffer was just allocated to the desired
            // size.
            LOG.e(
                    TAG,
                    "Buffer overflow while attempting to process handshake message. Attempting to"
                            + " close connection.",
                    e);
            return closeConnection(applicationData, packetData);
        }
        applicationData.flip();
        packetData.flip();

        TlsResult tlsResult = new TlsResult(TLS_STATUS_FAILURE);

        processingLoop:
        while (true) {
            switch (mHandshakeStatus) {
                case NEED_UNWRAP:
                    tlsResult = unwrap(applicationData, packetData);
                    continue;
                case NEED_TASK:
                    mSslEngine.getDelegatedTask().run();
                    mHandshakeStatus = mSslEngine.getHandshakeStatus();
                    continue;
                case NEED_WRAP:
                    packetData.clear();
                    tlsResult = wrap(applicationData, packetData);
                    if (mHandshakeStatus == HandshakeStatus.FINISHED) {
                        mHandshakeStatus = mSslEngine.getHandshakeStatus();
                    }
                    break processingLoop;
                default:
                    // If the status is NOT_HANDSHAKING, this is unexpected, and is treated as a
                    // failure. FINISHED can never be reached here because it is handled in
                    // NEED_WRAP/NEED_UNWRAP
                    break processingLoop;
            }
        }

        return tlsResult;
    }

    /**
     * Decrypts incoming data during a TLS session
     *
     * @param data the data to decrypt
     * @return a tls result containing the decrypted data and status of operation
     */
    public TlsResult processIncomingData(byte[] data) {
        // TODO(b/163561894): Revert to persistent ByteBuffers in TLS Session
        ByteBuffer applicationData = ByteBuffer.allocate(mSslSession.getApplicationBufferSize());
        ByteBuffer packetData = ByteBuffer.wrap(data);
        return unwrap(applicationData, packetData);
    }

    /**
     * Encrypts outbound data during a TLS session
     *
     * @param data the data to encrypt
     * @return a tls result containing the encrypted data and status of operation
     */
    public TlsResult processOutgoingData(byte[] data) {
        // TODO(b/163561894): Revert to persistent ByteBuffers in TLS Session
        ByteBuffer applicationData = ByteBuffer.wrap(data);
        ByteBuffer packetData = ByteBuffer.allocate(mSslSession.getPacketBufferSize());
        return wrap(applicationData, packetData);
    }

    /**
     * Unwraps data during a TLS session either during a handshake or for decryption purposes.
     *
     * @param applicationData a destination buffer with decrypted or processed data
     * @param packetData a bytebuffer containing inbound data from the server
     * @return a tls result containing the unwrapped message and status of operation
     */
    private TlsResult unwrap(ByteBuffer applicationData, ByteBuffer packetData) {
        SSLEngineResult result;
        try {
            result = mSslEngine.unwrap(packetData, applicationData);
        } catch (SSLException e) {
            LOG.e(TAG, "Encountered an issue while unwrapping data. Connection will be closed.", e);
            return closeConnection(applicationData, packetData);
        }

        mHandshakeStatus = result.getHandshakeStatus();
        if (result.getStatus() != Status.OK) {
            return closeConnection(applicationData, packetData);
        }

        return new TlsResult(getByteArrayFromBuffer(applicationData), TLS_STATUS_SUCCESS);
    }

    /**
     * Wraps data during a TLS session either during a handshake or for encryption purposes.
     *
     * @param applicationData a bytebuffer containing data to encrypt or process
     * @param packetData a destination buffer for outbound data
     * @return a tls result containing the wrapped message and status of operation
     */
    private TlsResult wrap(ByteBuffer applicationData, ByteBuffer packetData) {
        SSLEngineResult result;
        try {
            result = mSslEngine.wrap(applicationData, packetData);
        } catch (SSLException e) {
            LOG.e(TAG, "Encountered an issue while wrapping data. Connection will be closed.", e);
            return closeConnection(applicationData, packetData);
        }

        mHandshakeStatus = result.getHandshakeStatus();
        if (result.getStatus() != Status.OK) {
            return closeConnection(applicationData, packetData);
        }

        return new TlsResult(
                getByteArrayFromBuffer(packetData),
                (mHandshakeStatus == HandshakeStatus.FINISHED)
                        ? TLS_STATUS_TUNNEL_ESTABLISHED
                        : TLS_STATUS_SUCCESS);
    }

    /**
     * Attempts to close the TLS tunnel.
     *
     * <p>Once a session has been closed, it cannot be reopened.
     *
     * @param applicationData a bytebuffer for the client side
     * @param packetData a bytebuffer for the server side
     * @return a tls result with the status of the operation as well as a potential closing message
     */
    private TlsResult closeConnection(ByteBuffer applicationData, ByteBuffer packetData) {
        try {
            mSslEngine.closeInbound();
        } catch (SSLException e) {
            LOG.e(TAG, "Error occurred when trying to close inbound.", e);
        }
        mSslEngine.closeOutbound();

        mHandshakeStatus = mSslEngine.getHandshakeStatus();

        if (mHandshakeStatus != HandshakeStatus.NEED_WRAP) {
            return new TlsResult(TLS_STATUS_CLOSED);
        }

        applicationData.clear();
        packetData.clear();

        SSLEngineResult result;
        while (mHandshakeStatus == HandshakeStatus.NEED_WRAP) {
            try {
                // the wrap is handled internally in order to preserve data in the buffers as they
                // are cleared in the beginning of the closeConnection call
                result = mSslEngine.wrap(applicationData, packetData);
            } catch (SSLException e) {
                LOG.e(
                        TAG,
                        "Wrap operation failed whilst attempting to flush out data during a close.",
                        e);
                return new TlsResult(TLS_STATUS_FAILURE);
            }

            mHandshakeStatus = result.getHandshakeStatus();
            if (result.getStatus() == Status.BUFFER_OVERFLOW
                    || result.getStatus() == Status.BUFFER_UNDERFLOW) {
                // an overflow or underflow at this point should not occur. if one does, terminate
                LOG.e(
                        TAG,
                        "Experienced an overflow or underflow while trying to close the TLS"
                                + " connection.");
                return new TlsResult(TLS_STATUS_FAILURE);
            }
        }

        return new TlsResult(getByteArrayFromBuffer(packetData), TLS_STATUS_CLOSED);
    }

    /**
     * Retrieves a byte array from a given byte buffer
     *
     * @param buffer the byte buffer to get the array from
     * @return a byte array
     */
    @VisibleForTesting
    public static byte[] getByteArrayFromBuffer(ByteBuffer buffer) {
        return Arrays.copyOfRange(buffer.array(), 0, buffer.position());
    }

    /**
     * TlsResult encapsulates the results of a TlsSession operation.
     *
     * <p>It contains the status result of the TLS session and the data that accompanies it
     */
    public class TlsResult {
        public final byte[] data;
        public final @TlsStatus int status;

        public TlsResult(byte[] data, @TlsStatus int status) {
            this.data = data;
            this.status = status;
        }

        public TlsResult(@TlsStatus int status) {
            this(new byte[0], status);
        }
    }
}
