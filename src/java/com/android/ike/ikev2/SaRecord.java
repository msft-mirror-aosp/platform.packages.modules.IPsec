/*
 * Copyright (C) 2019 The Android Open Source Project
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
package com.android.ike.ikev2;

import android.annotation.Nullable;
import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.SecurityParameterIndex;
import android.net.IpSecManager.SpiUnavailableException;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.IpSecTransform;
import android.util.Log;

import com.android.ike.ikev2.IkeLocalRequestScheduler.LocalRequest;
import com.android.ike.ikev2.IkeSessionStateMachine.IkeSecurityParameterIndex;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.message.IkeKePayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.internal.annotations.VisibleForTesting;

import dalvik.system.CloseGuard;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * SaRecord represents common information of an IKE SA and a Child SA.
 *
 * <p>When doing rekey, there can be multiple SAs in the same IkeSessionStateMachine or
 * ChildSessionStateMachine, where they use same cryptographic algorithms but with different keys.
 * We store cryptographic algorithms and unchanged SA configurations in IkeSessionOptions or
 * ChildSessionOptions and store changed information including keys, SPIs, and nonces in SaRecord.
 */
public abstract class SaRecord implements AutoCloseable {
    private static ISaRecordHelper sSaRecordHelper = new SaRecordHelper();
    private static IIpSecTransformHelper sIpSecTransformHelper = new IpSecTransformHelper();

    /** Flag indicates if this SA is locally initiated */
    public final boolean isLocalInit;

    public final byte[] nonceInitiator;
    public final byte[] nonceResponder;

    private final byte[] mSkAi;
    private final byte[] mSkAr;
    private final byte[] mSkEi;
    private final byte[] mSkEr;

    private final LocalRequest mFutureRekeyEvent;

    private final CloseGuard mCloseGuard = CloseGuard.get();

    /** Package private */
    SaRecord(
            boolean localInit,
            byte[] nonceInit,
            byte[] nonceResp,
            byte[] skAi,
            byte[] skAr,
            byte[] skEi,
            byte[] skEr,
            LocalRequest futureRekeyEvent) {
        isLocalInit = localInit;
        nonceInitiator = nonceInit;
        nonceResponder = nonceResp;

        mSkAi = skAi;
        mSkAr = skAr;
        mSkEi = skEi;
        mSkEr = skEr;

        mFutureRekeyEvent = futureRekeyEvent;

        mCloseGuard.open("close");
    }

    /**
     * Get the integrity key for calculate integrity checksum for an outbound packet.
     *
     * @return the integrity key in a byte array, which will be empty if integrity algorithm is not
     *     used in this SA.
     */
    public byte[] getOutboundIntegrityKey() {
        return isLocalInit ? mSkAi : mSkAr;
    }

    /**
     * Get the integrity key to authenticate an inbound packet.
     *
     * @return the integrity key in a byte array, which will be empty if integrity algorithm is not
     *     used in this SA.
     */
    public byte[] getInboundIntegrityKey() {
        return isLocalInit ? mSkAr : mSkAi;
    }

    /**
     * Get the encryption key for protecting an outbound packet.
     *
     * @return the encryption key in a byte array.
     */
    public byte[] getOutboundEncryptionKey() {
        return isLocalInit ? mSkEi : mSkEr;
    }

    /**
     * Get the decryption key for an inbound packet.
     *
     * @return the decryption key in a byte array.
     */
    public byte[] getInboundDecryptionKey() {
        return isLocalInit ? mSkEr : mSkEi;
    }

    /** Check that the SaRecord was closed properly. */
    @Override
    protected void finalize() throws Throwable {
        if (mCloseGuard != null) {
            mCloseGuard.warnIfOpen();
        }
        close();
    }

    @Override
    public void close() {
        mFutureRekeyEvent.cancel();
    }

    /** Package private */
    LocalRequest getFutureRekeyEvent() {
        return mFutureRekeyEvent;
    }

    /** Package private */
    @VisibleForTesting
    static void setSaRecordHelper(ISaRecordHelper helper) {
        sSaRecordHelper = helper;
    }

    /** Package private */
    @VisibleForTesting
    static void setIpSecTransformHelper(IIpSecTransformHelper helper) {
        sIpSecTransformHelper = helper;
    }

    /**
     * SaRecordHelper implements methods for constructing SaRecord.
     *
     * <p>Package private
     */
    static class SaRecordHelper implements ISaRecordHelper {
        @Override
        public IkeSaRecord makeFirstIkeSaRecord(
                IkeMessage initRequest,
                IkeMessage initResponse,
                IkeSaRecordConfig ikeSaRecordConfig)
                throws GeneralSecurityException {
            // Extract nonces
            byte[] nonceInit =
                    initRequest.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class)
                            .nonceData;
            byte[] nonceResp =
                    initResponse.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class)
                            .nonceData;

            // Get SKEYSEED
            byte[] sharedDhKey = getSharedKey(initRequest, initResponse);
            byte[] sKeySeed =
                    ikeSaRecordConfig.prf.generateSKeySeed(nonceInit, nonceResp, sharedDhKey);

            return makeIkeSaRecord(sKeySeed, nonceInit, nonceResp, ikeSaRecordConfig);
        }

        @Override
        public IkeSaRecord makeRekeyedIkeSaRecord(
                IkeSaRecord oldSaRecord,
                IkeMacPrf oldPrf,
                IkeMessage rekeyRequest,
                IkeMessage rekeyResponse,
                IkeSaRecordConfig ikeSaRecordConfig)
                throws GeneralSecurityException {
            // Extract nonces
            byte[] nonceInit =
                    rekeyRequest.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class)
                            .nonceData;
            byte[] nonceResp =
                    rekeyResponse.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class)
                            .nonceData;

            // Get SKEYSEED
            IkeMessage localMsg = ikeSaRecordConfig.isLocalInit ? rekeyRequest : rekeyResponse;
            IkeMessage remoteMsg = ikeSaRecordConfig.isLocalInit ? rekeyResponse : rekeyRequest;

            byte[] sharedDhKey = getSharedKey(localMsg, remoteMsg);
            byte[] sKeySeed =
                    oldPrf.generateRekeyedSKeySeed(
                            oldSaRecord.mSkD, nonceInit, nonceResp, sharedDhKey);

            return makeIkeSaRecord(sKeySeed, nonceInit, nonceResp, ikeSaRecordConfig);
        }

        private byte[] getSharedKey(IkeMessage keLocalMessage, IkeMessage keRemoteMessage)
                throws GeneralSecurityException {
            IkeKePayload keLocalPayload =
                    keLocalMessage.getPayloadForType(
                            IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);
            IkeKePayload keRemotePayload =
                    keRemoteMessage.getPayloadForType(
                            IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);

            return IkeKePayload.getSharedKey(
                    keLocalPayload.localPrivateKey, keRemotePayload.keyExchangeData);
        }

        /**
         * Package private method for calculating keys and construct IkeSaRecord.
         *
         * @see <a href="https://tools.ietf.org/html/rfc7296#section-2.13">RFC 7296, Internet Key
         *     Exchange Protocol Version 2 (IKEv2), Generating Keying Material</a>
         */
        @VisibleForTesting
        IkeSaRecord makeIkeSaRecord(
                byte[] sKeySeed,
                byte[] nonceInit,
                byte[] nonceResp,
                IkeSaRecordConfig ikeSaRecordConfig) {
            // Build data to sign for generating the keying material.
            ByteBuffer bufferToSign =
                    ByteBuffer.allocate(
                            nonceInit.length + nonceResp.length + 2 * IkePayload.SPI_LEN_IKE);

            IkeSecurityParameterIndex initSpi = ikeSaRecordConfig.initSpi;
            IkeSecurityParameterIndex respSpi = ikeSaRecordConfig.respSpi;
            IkeMacPrf prf = ikeSaRecordConfig.prf;
            int integrityKeyLength = ikeSaRecordConfig.integrityKeyLength;
            int encryptionKeyLength = ikeSaRecordConfig.encryptionKeyLength;

            bufferToSign
                    .put(nonceInit)
                    .put(nonceResp)
                    .putLong(initSpi.getSpi())
                    .putLong(respSpi.getSpi());

            // Get length of the keying material according to RFC 7296, 2.13 and 2.14. The length of
            // SK_D is always equal to the length of PRF key.
            int skDLength = prf.getKeyLength();
            int keyMaterialLen =
                    skDLength
                            + 2 * integrityKeyLength
                            + 2 * encryptionKeyLength
                            + 2 * prf.getKeyLength();
            byte[] keyMat = prf.generateKeyMat(sKeySeed, bufferToSign.array(), keyMaterialLen);

            // Extract keys.
            byte[] skD = new byte[skDLength];
            byte[] skAi = new byte[integrityKeyLength];
            byte[] skAr = new byte[integrityKeyLength];
            byte[] skEi = new byte[encryptionKeyLength];
            byte[] skEr = new byte[encryptionKeyLength];
            byte[] skPi = new byte[prf.getKeyLength()];
            byte[] skPr = new byte[prf.getKeyLength()];

            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMat);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            return new IkeSaRecord(
                    initSpi,
                    respSpi,
                    true /*localInit*/,
                    nonceInit,
                    nonceResp,
                    skD,
                    skAi,
                    skAr,
                    skEi,
                    skEr,
                    skPi,
                    skPr,
                    ikeSaRecordConfig.futureRekeyEvent);
        }

        @Override
        public ChildSaRecord makeChildSaRecord(
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                ChildSaRecordConfig childSaRecordConfig)
                throws GeneralSecurityException, ResourceUnavailableException,
                        SpiUnavailableException, IOException {
            // Extract nonces. Encoding/Decoding of payload list guarantees that there is only one
            // nonce payload in the reqPayloads and respPayloads lists
            byte[] nonceInit =
                    IkePayload.getPayloadForTypeInProvidedList(
                                    IkePayload.PAYLOAD_TYPE_NONCE,
                                    IkeNoncePayload.class,
                                    reqPayloads)
                            .nonceData;
            byte[] nonceResp =
                    IkePayload.getPayloadForTypeInProvidedList(
                                    IkePayload.PAYLOAD_TYPE_NONCE,
                                    IkeNoncePayload.class,
                                    respPayloads)
                            .nonceData;

            // Check if KE Payload exists and get DH shared key. Encoding/Decoding of payload list
            // guarantees that there is either no KE payload in the reqPayloads and respPayloads
            // lists, or only one KE payload in each list.
            byte[] sharedDhKey = new byte[0];
            IkeKePayload keInitPayload =
                    IkePayload.getPayloadForTypeInProvidedList(
                            IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class, reqPayloads);
            if (keInitPayload != null) {
                IkeKePayload keRespPayload =
                        IkePayload.getPayloadForTypeInProvidedList(
                                IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class, respPayloads);
                sharedDhKey =
                        IkeKePayload.getSharedKey(
                                keInitPayload.localPrivateKey, keRespPayload.keyExchangeData);
            }

            return makeChildSaRecord(sharedDhKey, nonceInit, nonceResp, childSaRecordConfig);
        }
        /**
         * Package private method for calculating keys, build IpSecTransforms and construct
         * ChildSaRecord.
         *
         * @see <a href="https://tools.ietf.org/html/rfc7296#section-2.17">RFC 7296, Internet Key
         *     Exchange Protocol Version 2 (IKEv2), Generating Keying Material for Child SAs</a>
         */
        @VisibleForTesting
        ChildSaRecord makeChildSaRecord(
                byte[] sharedKey,
                byte[] nonceInit,
                byte[] nonceResp,
                ChildSaRecordConfig childSaRecordConfig)
                throws ResourceUnavailableException, SpiUnavailableException, IOException {
            // Build data to sign for generating the keying material.
            ByteBuffer bufferToSign =
                    ByteBuffer.allocate(sharedKey.length + nonceInit.length + nonceResp.length);
            bufferToSign.put(sharedKey).put(nonceInit).put(nonceResp);

            // Get length of the keying material according to RFC 7296, 2.17.
            int encryptionKeyLength = childSaRecordConfig.encryptionAlgo.getKeyLength();
            int integrityKeyLength =
                    childSaRecordConfig.hasIntegrityAlgo
                            ? childSaRecordConfig.integrityAlgo.getKeyLength()
                            : 0;
            int keyMaterialLen = 2 * encryptionKeyLength + 2 * integrityKeyLength;
            byte[] keyMat =
                    childSaRecordConfig.ikePrf.generateKeyMat(
                            childSaRecordConfig.skD, bufferToSign.array(), keyMaterialLen);

            // Extract keys according to the order that keys carrying data from initiator to
            // responder are taken before keys for the other direction and encryption keys are taken
            // before integrity keys.
            byte[] skEi = new byte[encryptionKeyLength];
            byte[] skAi = new byte[integrityKeyLength];
            byte[] skEr = new byte[encryptionKeyLength];
            byte[] skAr = new byte[integrityKeyLength];

            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMat);
            keyMatBuffer.get(skEi).get(skAi).get(skEr).get(skAr);

            IpSecTransform initTransform = null;
            IpSecTransform respTransform = null;
            try {
                // Build IpSecTransform
                initTransform =
                        sIpSecTransformHelper.makeIpSecTransform(
                                childSaRecordConfig.context,
                                childSaRecordConfig.initAddress,
                                childSaRecordConfig.udpEncapSocket,
                                childSaRecordConfig.initSpi,
                                childSaRecordConfig.integrityAlgo,
                                childSaRecordConfig.encryptionAlgo,
                                skAi,
                                skEi,
                                childSaRecordConfig.isTransport);
                respTransform =
                        sIpSecTransformHelper.makeIpSecTransform(
                                childSaRecordConfig.context,
                                childSaRecordConfig.respAddress,
                                childSaRecordConfig.udpEncapSocket,
                                childSaRecordConfig.respSpi,
                                childSaRecordConfig.integrityAlgo,
                                childSaRecordConfig.encryptionAlgo,
                                skAr,
                                skEr,
                                childSaRecordConfig.isTransport);

                int initSpi = childSaRecordConfig.initSpi.getSpi();
                int respSpi = childSaRecordConfig.respSpi.getSpi();

                boolean isLocalInit = childSaRecordConfig.isLocalInit;
                int inSpi = isLocalInit ? initSpi : respSpi;
                int outSpi = isLocalInit ? respSpi : initSpi;
                IpSecTransform inTransform = isLocalInit ? initTransform : respTransform;
                IpSecTransform outTransform = isLocalInit ? respTransform : initTransform;

                return new ChildSaRecord(
                        inSpi,
                        outSpi,
                        isLocalInit,
                        nonceInit,
                        nonceResp,
                        skAi,
                        skAr,
                        skEi,
                        skEr,
                        inTransform,
                        outTransform);

            } catch (Exception e) {
                if (initTransform != null) initTransform.close();
                if (respTransform != null) initTransform.close();
                throw e;
            }
        }
    }

    /**
     * IpSecTransformHelper implements the IIpSecTransformHelper interface for constructing {@link
     * IpSecTransform}}.
     *
     * <p>Package private
     */
    static class IpSecTransformHelper implements IIpSecTransformHelper {
        private static final String TAG = "IpSecTransformHelper";

        @Override
        public IpSecTransform makeIpSecTransform(
                Context context,
                InetAddress sourceAddress,
                UdpEncapsulationSocket udpEncapSocket,
                IpSecManager.SecurityParameterIndex spi,
                @Nullable IkeMacIntegrity integrityAlgo,
                IkeCipher encryptionAlgo,
                byte[] integrityKey,
                byte[] encryptionKey,
                boolean isTransport)
                throws ResourceUnavailableException, SpiUnavailableException, IOException {
            IpSecTransform.Builder builder = new IpSecTransform.Builder(context);

            if (encryptionAlgo.isAead()) {
                builder.setAuthenticatedEncryption(
                        encryptionAlgo.buildIpSecAlgorithmWithKey(encryptionKey));
            } else {
                builder.setEncryption(encryptionAlgo.buildIpSecAlgorithmWithKey(encryptionKey));
                builder.setAuthentication(integrityAlgo.buildIpSecAlgorithmWithKey(integrityKey));
            }

            if (udpEncapSocket != null && sourceAddress instanceof Inet6Address) {
                Log.wtf(TAG, "Kernel does not support UDP encapsulation for IPv6 SAs");
            }
            if (udpEncapSocket != null && sourceAddress instanceof Inet4Address) {
                builder.setIpv4Encapsulation(udpEncapSocket, udpEncapSocket.getPort());
            }

            if (isTransport) {
                return builder.buildTransportModeTransform(sourceAddress, spi);
            } else {
                return builder.buildTunnelModeTransform(sourceAddress, spi);
            }
        }
    }

    /** Package private class to group parameters for building a ChildSaRecord. */
    @VisibleForTesting
    static final class ChildSaRecordConfig {
        public final Context context;
        public final SecurityParameterIndex initSpi;
        public final SecurityParameterIndex respSpi;
        public final InetAddress initAddress;
        public final InetAddress respAddress;
        @Nullable public final UdpEncapsulationSocket udpEncapSocket;
        public final IkeMacPrf ikePrf;
        @Nullable public final IkeMacIntegrity integrityAlgo;
        public final IkeCipher encryptionAlgo;
        public final byte[] skD;
        public final boolean isTransport;
        public final boolean isLocalInit;
        public final boolean hasIntegrityAlgo;

        ChildSaRecordConfig(
                Context context,
                SecurityParameterIndex initSpi,
                SecurityParameterIndex respSpi,
                InetAddress localAddress,
                InetAddress remoteAddress,
                @Nullable UdpEncapsulationSocket udpEncapSocket,
                IkeMacPrf ikePrf,
                @Nullable IkeMacIntegrity integrityAlgo,
                IkeCipher encryptionAlgo,
                byte[] skD,
                boolean isTransport,
                boolean isLocalInit) {
            this.context = context;
            this.initSpi = initSpi;
            this.respSpi = respSpi;
            this.initAddress = isLocalInit ? localAddress : remoteAddress;
            this.respAddress = isLocalInit ? remoteAddress : localAddress;
            this.udpEncapSocket = udpEncapSocket;
            this.ikePrf = ikePrf;
            this.integrityAlgo = integrityAlgo;
            this.encryptionAlgo = encryptionAlgo;
            this.skD = skD;
            this.isTransport = isTransport;
            this.isLocalInit = isLocalInit;
            hasIntegrityAlgo = (integrityAlgo != null);
        }
    }

    /** IkeSaRecord represents an IKE SA. */
    public static class IkeSaRecord extends SaRecord implements Comparable<IkeSaRecord> {
        /** SPI of IKE SA initiator */
        private final IkeSecurityParameterIndex mInitiatorSpiResource;
        /** SPI of IKE SA responder */
        private final IkeSecurityParameterIndex mResponderSpiResource;

        private final byte[] mSkD;
        private final byte[] mSkPi;
        private final byte[] mSkPr;

        private int mLocalRequestMessageId;
        private int mRemoteRequestMessageId;

        /** Package private */
        IkeSaRecord(
                IkeSecurityParameterIndex initSpi,
                IkeSecurityParameterIndex respSpi,
                boolean localInit,
                byte[] nonceInit,
                byte[] nonceResp,
                byte[] skD,
                byte[] skAi,
                byte[] skAr,
                byte[] skEi,
                byte[] skEr,
                byte[] skPi,
                byte[] skPr,
                LocalRequest futureRekeyEvent) {
            super(localInit, nonceInit, nonceResp, skAi, skAr, skEi, skEr, futureRekeyEvent);

            mInitiatorSpiResource = initSpi;
            mResponderSpiResource = respSpi;

            mSkD = skD;
            mSkPi = skPi;
            mSkPr = skPr;

            mLocalRequestMessageId = 0;
            mRemoteRequestMessageId = 0;
        }

        /**
         * Package private interface for IkeSessionStateMachien to construct an IkeSaRecord
         * instance.
         */
        static IkeSaRecord makeFirstIkeSaRecord(
                IkeMessage initRequest,
                IkeMessage initResponse,
                IkeSecurityParameterIndex initSpi,
                IkeSecurityParameterIndex respSpi,
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength,
                LocalRequest futureRekeyEvent)
                throws GeneralSecurityException {
            return sSaRecordHelper.makeFirstIkeSaRecord(
                    initRequest,
                    initResponse,
                    new IkeSaRecordConfig(
                            initSpi,
                            respSpi,
                            prf,
                            integrityKeyLength,
                            encryptionKeyLength,
                            true /*isLocalInit*/,
                            futureRekeyEvent));
        }

        /** Package private */
        static IkeSaRecord makeRekeyedIkeSaRecord(
                IkeSaRecord oldSaRecord,
                IkeMacPrf oldPrf,
                IkeMessage rekeyRequest,
                IkeMessage rekeyResponse,
                IkeSecurityParameterIndex initSpi,
                IkeSecurityParameterIndex respSpi,
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength,
                boolean isLocalInit,
                LocalRequest futureRekeyEvent)
                throws GeneralSecurityException {
            return sSaRecordHelper.makeRekeyedIkeSaRecord(
                    oldSaRecord,
                    oldPrf,
                    rekeyRequest,
                    rekeyResponse,
                    new IkeSaRecordConfig(
                            initSpi,
                            respSpi,
                            prf,
                            integrityKeyLength,
                            encryptionKeyLength,
                            isLocalInit,
                            futureRekeyEvent));
        }

        /** Package private */
        long getInitiatorSpi() {
            return mInitiatorSpiResource.getSpi();
        }

        /** Package private */
        long getResponderSpi() {
            return mResponderSpiResource.getSpi();
        }

        /** Package private */
        long getLocalSpi() {
            return isLocalInit ? mInitiatorSpiResource.getSpi() : mResponderSpiResource.getSpi();
        }

        /** Package private */
        long getRemoteSpi() {
            return isLocalInit ? mResponderSpiResource.getSpi() : mInitiatorSpiResource.getSpi();
        }

        /** Package private */
        byte[] getSkD() {
            return mSkD;
        }

        /**
         * Get the PRF key of IKE initiator for building an outbound Auth Payload.
         *
         * @return the PRF key in a byte array.
         */
        public byte[] getSkPi() {
            return mSkPi;
        }

        /**
         * Get the PRF key of IKE responder for validating an inbound Auth Payload.
         *
         * @return the PRF key in a byte array.
         */
        public byte[] getSkPr() {
            return mSkPr;
        }

        /**
         * Compare with a specific IkeSaRecord
         *
         * @param record IkeSaRecord to be compared.
         * @return a negative integer if input IkeSaRecord contains lowest nonce; a positive integer
         *     if this IkeSaRecord has lowest nonce; return zero if lowest nonces of two
         *     IkeSaRecords match.
         */
        public int compareTo(IkeSaRecord record) {
            // TODO: Implement it b/122924815.
            return 1;
        }

        /**
         * Get current message ID for the local requesting window.
         *
         * <p>Called for building an outbound request or for validating the message ID of an inbound
         * response.
         *
         * @return the local request message ID.
         */
        public int getLocalRequestMessageId() {
            return mLocalRequestMessageId;
        }

        /**
         * Get current message ID for the remote requesting window.
         *
         * <p>Called for validating the message ID of an inbound request. If the message ID of the
         * inbound request is smaller than the current remote message ID by one, it means the
         * message is a retransmitted request.
         *
         * @return the remote request message ID
         */
        public int getRemoteRequestMessageId() {
            return mRemoteRequestMessageId;
        }

        /**
         * Increment the local request message ID by one.
         *
         * <p>It should be called when IKE library has received an authenticated and protected
         * response with the correct local request message ID.
         */
        public void incrementLocalRequestMessageId() {
            mLocalRequestMessageId++;
        }

        /**
         * Increment the remote request message ID by one.
         *
         * <p>It should be called when IKE library has received an authenticated and protected
         * request with the correct remote request message ID.
         */
        public void incrementRemoteRequestMessageId() {
            mRemoteRequestMessageId++;
        }

        /** Release IKE SPI resource. */
        @Override
        public void close() {
            super.close();
            mInitiatorSpiResource.close();
            mResponderSpiResource.close();
        }
    }

    /** Package private class that groups parameters to construct an IkeSaRecord instance. */
    @VisibleForTesting
    static class IkeSaRecordConfig {
        public final IkeSecurityParameterIndex initSpi;
        public final IkeSecurityParameterIndex respSpi;
        public final IkeMacPrf prf;
        public final int integrityKeyLength;
        public final int encryptionKeyLength;
        public final boolean isLocalInit;
        public final LocalRequest futureRekeyEvent;

        IkeSaRecordConfig(
                IkeSecurityParameterIndex initSpi,
                IkeSecurityParameterIndex respSpi,
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength,
                boolean isLocalInit,
                LocalRequest futureRekeyEvent) {
            this.initSpi = initSpi;
            this.respSpi = respSpi;
            this.prf = prf;
            this.integrityKeyLength = integrityKeyLength;
            this.encryptionKeyLength = encryptionKeyLength;
            this.isLocalInit = isLocalInit;
            this.futureRekeyEvent = futureRekeyEvent;
        }
    }

    /** ChildSaRecord represents an Child SA. */
    public static class ChildSaRecord extends SaRecord implements Comparable<ChildSaRecord> {
        /** Locally generated SPI for receiving IPsec Packet. */
        private final int mInboundSpi;
        /** Remotely generated SPI for sending IPsec Packet. */
        private final int mOutboundSpi;

        /** IPsec Transform applied to traffic towards the host. */
        private final IpSecTransform mInboundTransform;
        /** IPsec Transform applied to traffic from the host. */
        private final IpSecTransform mOutboundTransform;

        /** Package private */
        ChildSaRecord(
                int inSpi,
                int outSpi,
                boolean localInit,
                byte[] nonceInit,
                byte[] nonceResp,
                byte[] skAi,
                byte[] skAr,
                byte[] skEi,
                byte[] skEr,
                IpSecTransform inTransform,
                IpSecTransform outTransform) {
            super(
                    localInit,
                    nonceInit,
                    nonceResp,
                    skAi,
                    skAr,
                    skEi,
                    skEr,
                    null /*futureRekeyEvent*/);

            // TODO: Support passing futureRekeyEvent

            mInboundSpi = inSpi;
            mOutboundSpi = outSpi;
            mInboundTransform = inTransform;
            mOutboundTransform = outTransform;
        }

        /**
         * Package private interface for ChildSessionStateMachine to construct a ChildSaRecord
         * instance.
         */
        static ChildSaRecord makeChildSaRecord(
                Context context,
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                SecurityParameterIndex initSpi,
                SecurityParameterIndex respSpi,
                InetAddress localAddress,
                InetAddress remoteAddress,
                @Nullable UdpEncapsulationSocket udpEncapSocket,
                IkeMacPrf prf,
                @Nullable IkeMacIntegrity integrityAlgo,
                IkeCipher encryptionAlgo,
                byte[] skD,
                boolean isTransport,
                boolean isLocalInit)
                throws GeneralSecurityException, ResourceUnavailableException,
                        SpiUnavailableException, IOException {
            return sSaRecordHelper.makeChildSaRecord(
                    reqPayloads,
                    respPayloads,
                    new ChildSaRecordConfig(
                            context,
                            initSpi,
                            respSpi,
                            localAddress,
                            remoteAddress,
                            udpEncapSocket,
                            prf,
                            integrityAlgo,
                            encryptionAlgo,
                            skD,
                            isTransport,
                            isLocalInit));
        }

        /** Package private */
        int getLocalSpi() {
            return mInboundSpi;
        }

        /** Package private */
        int getRemoteSpi() {
            return mOutboundSpi;
        }

        /** Package private */
        IpSecTransform getInboundIpSecTransform() {
            return mInboundTransform;
        }

        /** Package private */
        IpSecTransform getOutboundIpSecTransform() {
            return mOutboundTransform;
        }

        /**
         * Compare with a specific ChildSaRecord
         *
         * @param record ChildSaRecord to be compared.
         * @return a negative integer if input ChildSaRecord contains lowest nonce; a positive
         *     integer if this ChildSaRecord has lowest nonce; return zero if lowest nonces of two
         *     ChildSaRecord match.
         */
        public int compareTo(ChildSaRecord record) {
            // TODO: Implement it b/122924815
            return 1;
        }

        /** Release IpSecTransform pair. */
        @Override
        public void close() {
            mInboundTransform.close();
            mOutboundTransform.close();
        }
    }

    /**
     * ISaRecordHelper provides a package private interface for constructing SaRecord.
     *
     * <p>ISaRecordHelper exists so that the interface is injectable for testing.
     */
    interface ISaRecordHelper {
        /**
         * Construct IkeSaRecord as results of IKE initial exchange.
         *
         * @param initRequest IKE_INIT request.
         * @param initResponse IKE_INIT request.
         * @param ikeSaRecordConfig that contains IKE SPI resources and negotiated algorithm
         *     information for constructing an IkeSaRecord instance.
         * @return ikeSaRecord for initial IKE SA.
         * @throws GeneralSecurityException if the DH public key in the response is invalid.
         */
        IkeSaRecord makeFirstIkeSaRecord(
                IkeMessage initRequest,
                IkeMessage initResponse,
                IkeSaRecordConfig ikeSaRecordConfig)
                throws GeneralSecurityException;

        /**
         * Construct new IkeSaRecord when doing rekey.
         *
         * @param oldSaRecord old IKE SA
         * @param oldPrf the PRF function from the old SA
         * @param rekeyRequest Rekey IKE request.
         * @param rekeyResponse Rekey IKE response.
         * @param ikeSaRecordConfig that contains IKE SPI resources and negotiated algorithm
         *     information for constructing an IkeSaRecord instance.
         * @return ikeSaRecord for new IKE SA.
         */
        IkeSaRecord makeRekeyedIkeSaRecord(
                IkeSaRecord oldSaRecord,
                IkeMacPrf oldPrf,
                IkeMessage rekeyRequest,
                IkeMessage rekeyResponse,
                IkeSaRecordConfig ikeSaRecordConfig)
                throws GeneralSecurityException;

        /**
         * Construct ChildSaRecord and generate IpSecTransform pairs.
         *
         * @param reqPayloads payload list in request.
         * @param respPayloads payload list in response.
         * @param childSaRecordConfig the grouped parameters for constructing ChildSaRecord.
         * @return new Child SA.
         */
        ChildSaRecord makeChildSaRecord(
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                ChildSaRecordConfig childSaRecordConfig)
                throws GeneralSecurityException, ResourceUnavailableException,
                        SpiUnavailableException, IOException;
    }

    /**
     * IIpSecTransformHelper provides a package private interface to construct {@link
     * IpSecTransform}
     *
     * <p>IIpSecTransformHelper exists so that the interface is injectable for testing.
     */
    @VisibleForTesting
    interface IIpSecTransformHelper {
        /**
         * Construct an instance of {@link IpSecTransform}
         *
         * @param context current context
         * @param sourceAddress the source {@code InetAddress} of traffic on sockets of interfaces
         *     that will use this transform
         * @param udpEncapSocket the UDP-Encap socket that allows IpSec traffic to pass through a
         *     NAT. Null if no NAT exists.
         * @param spi a unique {@link IpSecManager.SecurityParameterIndex} to identify transformed
         *     traffic
         * @param integrityAlgo specifying the authentication algorithm to be applied.
         * @param encryptionAlgo specifying the encryption algorithm or authenticated encryption
         *     algorithm to be applied.
         * @param integrityKey the negotiated authentication key to be applied.
         * @param encryptionKey the negotiated encryption key to be applied.
         * @param isTransport the flag indicates if a transport or a tunnel mode transform will be
         *     built.
         * @return an instance of {@link IpSecTransform}
         * @throws ResourceUnavailableException indicating that too many transforms are active
         * @throws SpiUnavailableException indicating the rare case where an SPI collides with an
         *     existing transform
         * @throws IOException indicating other errors
         */
        IpSecTransform makeIpSecTransform(
                Context context,
                InetAddress sourceAddress,
                UdpEncapsulationSocket udpEncapSocket,
                IpSecManager.SecurityParameterIndex spi,
                @Nullable IkeMacIntegrity integrityAlgo,
                IkeCipher encryptionAlgo,
                byte[] integrityKey,
                byte[] encryptionKey,
                boolean isTransport)
                throws ResourceUnavailableException, SpiUnavailableException, IOException;
    }
}
