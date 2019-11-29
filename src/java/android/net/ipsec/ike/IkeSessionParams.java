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

package android.net.ipsec.ike;

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.SystemApi;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.eap.EapSessionConfig;

import com.android.internal.net.ipsec.ike.message.IkePayload;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedList;
import java.util.List;

/**
 * IkeSessionParams contains all user provided configurations for negotiating an {@link IkeSession}.
 *
 * <p>Note that all negotiated configurations will be reused during rekey including SA Proposal and
 * lifetime.
 *
 * @hide
 */
@SystemApi
public final class IkeSessionParams {
    /** @hide */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({IKE_AUTH_METHOD_PSK, IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, IKE_AUTH_METHOD_EAP})
    public @interface IkeAuthMethod {}

    // Constants to describe user configured authentication methods.
    /** @hide */
    public static final int IKE_AUTH_METHOD_PSK = 1;
    /** @hide */
    public static final int IKE_AUTH_METHOD_PUB_KEY_SIGNATURE = 2;
    /** @hide */
    public static final int IKE_AUTH_METHOD_EAP = 3;

    private final InetAddress mServerAddress;
    private final UdpEncapsulationSocket mUdpEncapSocket;
    private final IkeSaProposal[] mSaProposals;

    private final IkeIdentification mLocalIdentification;
    private final IkeIdentification mRemoteIdentification;

    private final IkeAuthConfig mLocalAuthConfig;
    private final IkeAuthConfig mRemoteAuthConfig;

    private final boolean mIsIkeFragmentationSupported;

    private IkeSessionParams(
            InetAddress serverAddress,
            UdpEncapsulationSocket udpEncapsulationSocket,
            IkeSaProposal[] proposals,
            IkeIdentification localIdentification,
            IkeIdentification remoteIdentification,
            IkeAuthConfig localAuthConfig,
            IkeAuthConfig remoteAuthConfig,
            boolean isIkeFragmentationSupported) {
        mServerAddress = serverAddress;
        mUdpEncapSocket = udpEncapsulationSocket;
        mSaProposals = proposals;

        mLocalIdentification = localIdentification;
        mRemoteIdentification = remoteIdentification;

        mLocalAuthConfig = localAuthConfig;
        mRemoteAuthConfig = remoteAuthConfig;

        mIsIkeFragmentationSupported = isIkeFragmentationSupported;
    }

    /** @hide */
    public InetAddress getServerAddress() {
        return mServerAddress;
    }

    /** @hide */
    public UdpEncapsulationSocket getUdpEncapsulationSocket() {
        return mUdpEncapSocket;
    }

    /** @hide */
    public IkeSaProposal[] getSaProposals() {
        return mSaProposals;
    }

    /** @hide */
    public IkeIdentification getLocalIdentification() {
        return mLocalIdentification;
    }

    /** @hide */
    public IkeIdentification getRemoteIdentification() {
        return mRemoteIdentification;
    }

    /** @hide */
    public IkeAuthConfig getLocalAuthConfig() {
        return mLocalAuthConfig;
    }

    /** @hide */
    public IkeAuthConfig getRemoteAuthConfig() {
        return mRemoteAuthConfig;
    }

    /** @hide */
    public boolean isIkeFragmentationSupported() {
        return mIsIkeFragmentationSupported;
    }
    /**
     * This class contains common information of an IKEv2 authentication configuration.
     *
     * @hide
     */
    public abstract static class IkeAuthConfig {
        @IkeAuthMethod public final int mAuthMethod;

        protected IkeAuthConfig(@IkeAuthMethod int authMethod) {
            mAuthMethod = authMethod;
        }
    }

    /**
     * This class represents the configuration to support IKEv2 pre-shared-key-based authentication
     * of local or remote side.
     *
     * @hide
     */
    public static class IkeAuthPskConfig extends IkeAuthConfig {
        public final byte[] mPsk;

        private IkeAuthPskConfig(byte[] psk) {
            super(IKE_AUTH_METHOD_PSK);
            mPsk = psk;
        }
    }

    /**
     * This class represents the configuration to support IKEv2 public-key-signature-based
     * authentication of the remote side.
     *
     * @hide
     */
    public static class IkeAuthDigitalSignRemoteConfig extends IkeAuthConfig {
        public final TrustAnchor mTrustAnchor;

        private IkeAuthDigitalSignRemoteConfig(TrustAnchor trustAnchor) {
            super(IKE_AUTH_METHOD_PUB_KEY_SIGNATURE);
            mTrustAnchor = trustAnchor;
        }
    }

    /**
     * This class represents the configuration to support IKEv2 public-key-signature-based
     * authentication of the local side.
     *
     * @hide
     */
    public static class IkeAuthDigitalSignLocalConfig extends IkeAuthConfig {
        public final X509Certificate mEndCert;
        public final List<X509Certificate> mIntermediateCerts;
        public final PrivateKey mPrivateKey;

        private IkeAuthDigitalSignLocalConfig(
                X509Certificate clientEndCert,
                List<X509Certificate> clientIntermediateCerts,
                PrivateKey privateKey) {
            super(IKE_AUTH_METHOD_PUB_KEY_SIGNATURE);
            mEndCert = clientEndCert;
            mIntermediateCerts = clientIntermediateCerts;
            mPrivateKey = privateKey;
        }
    }

    /**
     * This class represents the configuration to support EAP authentication of the local side.
     *
     * <p>EAP MUST be used with IKEv2 public-key-based authentication of the responder to the
     * initiator. Currently IKE library does not support the IKEv2 protocol extension(RFC 5998)
     * which allows EAP methods that provide mutual authentication and key agreement to be used to
     * provide extensible responder authentication for IKEv2 based on methods other than public key
     * signatures.
     *
     * @see <a href="https://tools.ietf.org/html/rfc5998">RFC 5998, An Extension for EAP-Only
     *     Authentication in IKEv2</a>
     * @hide
     */
    public static class IkeAuthEapConfig extends IkeAuthConfig {
        public final EapSessionConfig mEapConfig;

        private IkeAuthEapConfig(EapSessionConfig eapConfig) {
            super(IKE_AUTH_METHOD_EAP);

            mEapConfig = eapConfig;
        }
    }

    /** This class can be used to incrementally construct a {@link IkeSessionParams}. */
    public static final class Builder {
        @NonNull private final List<IkeSaProposal> mSaProposalList = new LinkedList<>();

        @Nullable private InetAddress mServerAddress;
        @Nullable private UdpEncapsulationSocket mUdpEncapSocket;

        @Nullable private IkeIdentification mLocalIdentification;
        @Nullable private IkeIdentification mRemoteIdentification;

        @Nullable private IkeAuthConfig mLocalAuthConfig;
        @Nullable private IkeAuthConfig mRemoteAuthConfig;

        private boolean mIsIkeFragmentationSupported = false;

        /**
         * Sets the server address for the {@link IkeSessionParams} being built.
         *
         * @param serverAddress the IP address of the IKE server.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setServerAddress(@NonNull InetAddress serverAddress) {
            mServerAddress = serverAddress;
            return this;
        }

        /**
         * Sets the UDP Encapsulation socket for the {@link IkeSessionParams} being built.
         *
         * @param udpEncapsulationSocket the {@link IpSecManager.UdpEncapsulationSocket} for sending
         *     and receiving IKE messages.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setUdpEncapsulationSocket(
                @NonNull UdpEncapsulationSocket udpEncapsulationSocket) {
            mUdpEncapSocket = udpEncapsulationSocket;
            return this;
        }

        /**
         * Sets local IKE identification for the {@link IkeSessionParams} being built.
         *
         * @param identification the local IKE identification.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setLocalIdentification(@NonNull IkeIdentification identification) {
            mLocalIdentification = identification;
            return this;
        }

        /**
         * Sets remote IKE identification for the {@link IkeSessionParams} being built.
         *
         * @param identification the remote IKE identification.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setRemoteIdentification(@NonNull IkeIdentification identification) {
            mRemoteIdentification = identification;
            return this;
        }

        /**
         * Adds an IKE SA proposal to the {@link IkeSessionParams} being built.
         *
         * @param proposal IKE SA proposal.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder addSaProposal(@NonNull IkeSaProposal proposal) {
            if (proposal.getProtocolId() != IkePayload.PROTOCOL_ID_IKE) {
                throw new IllegalArgumentException(
                        "Expected IKE SA Proposal but received Child SA proposal");
            }
            mSaProposalList.add(proposal);
            return this;
        }

        /**
         * Configures the {@link IkeSession} to use pre-shared-key-based authentication.
         *
         * <p>Both client and server MUST be authenticated using the provided shared key. IKE
         * authentication will fail if the remote peer tries to use other authentication methods.
         *
         * <p>Callers MUST declare only one authentication method. Calling this function will
         * override the previously set authentication configuration.
         *
         * <p>Callers SHOULD NOT use this if any other authentication methods can be used; PSK-based
         * authentication is generally considered insecure.
         *
         * @param sharedKey the shared key.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setAuthPsk(@NonNull byte[] sharedKey) {
            mLocalAuthConfig = new IkeAuthPskConfig(sharedKey);
            mRemoteAuthConfig = new IkeAuthPskConfig(sharedKey);
            return this;
        }

        /**
         * Configures the {@link IkeSession} to use EAP authentication.
         *
         * <p>Not all EAP methods provide mutual authentication. As such EAP MUST be used in
         * conjunction with a public-key-signature-based authentication of the server to the client.
         *
         * <p>Callers MUST declare only one authentication method. Calling this function will
         * override the previously set authentication configuration.
         *
         * @see <a href="https://tools.ietf.org/html/rfc5280">RFC 5280, Internet X.509 Public Key
         *     Infrastructure Certificate and Certificate Revocation List (CRL) Profile</a>
         * @see <a href="https://tools.ietf.org/html/rfc5998">RFC 5998, An Extension for EAP-Only
         *     Authentication in IKEv2
         * @param serverCaCert the CA certificate for validating the received server certificate(s).
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setAuthEap(
                @NonNull X509Certificate serverCaCert, @NonNull EapSessionConfig eapConfig) {
            mLocalAuthConfig = new IkeAuthEapConfig(eapConfig);

            // The name constraints extension, defined in RFC 5280, indicates a name space within
            // which all subject names in subsequent certificates in a certification path MUST be
            // located.
            mRemoteAuthConfig =
                    new IkeAuthDigitalSignRemoteConfig(
                            new TrustAnchor(serverCaCert, null /*nameConstraints*/));

            // TODO: Investigate if we need to support the name constraints extension.

            return this;
        }

        /**
         * Configures the {@link IkeSession} to use public-key-signature-based authentication.
         *
         * <p>The public key included by the client end certificate and the private key used for
         * signing MUST be a matching key pair.
         *
         * <p>The IKE library will use the strongest signature algorithm supported by both sides.
         *
         * <p>Currenly only RSA digital signature is supported.
         *
         * @param serverCaCert the CA certificate for validating the received server certificate(s).
         * @param clientEndCert the end certificate for remote server to verify the locally
         *     generated signature.
         * @param clientPrivateKey private key to generate outbound digital signature. Only {@link
         *     RSAPrivateKey} is supported.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setAuthDigitalSignature(
                @NonNull X509Certificate serverCaCert,
                @NonNull X509Certificate clientEndCert,
                @NonNull PrivateKey clientPrivateKey) {
            return setAuthDigitalSignature(
                    serverCaCert,
                    clientEndCert,
                    new LinkedList<X509Certificate>(),
                    clientPrivateKey);
        }

        /**
         * Configures the {@link IkeSession} to use public-key-signature-based authentication.
         *
         * <p>The public key included by the client end certificate and the private key used for
         * signing MUST be a matching key pair.
         *
         * <p>The IKE library will use the strongest signature algorithm supported by both sides.
         *
         * <p>Currenly only RSA digital signature is supported.
         *
         * @param serverCaCert the CA certificate for validating the received server certificate(s).
         * @param clientEndCert the end certificate for remote server to verify locally generated
         *     signature.
         * @param clientIntermediateCerts intermediate certificates for the remote server to
         *     validate the end certificate.
         * @param clientPrivateKey private key to generate outbound digital signature. Only {@link
         *     RSAPrivateKey} is supported.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setAuthDigitalSignature(
                @NonNull X509Certificate serverCaCert,
                @NonNull X509Certificate clientEndCert,
                @NonNull List<X509Certificate> clientIntermediateCerts,
                @NonNull PrivateKey clientPrivateKey) {
            if (!(clientPrivateKey instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Unsupported private key type");
            }

            mLocalAuthConfig =
                    new IkeAuthDigitalSignLocalConfig(
                            clientEndCert, clientIntermediateCerts, clientPrivateKey);
            mRemoteAuthConfig =
                    new IkeAuthDigitalSignRemoteConfig(
                            new TrustAnchor(serverCaCert, null /*nameConstraints*/));
            return this;
        }

        /**
         * Validates and builds the {@link IkeSessionParams}.
         *
         * @return IkeSessionParams the validated IkeSessionParams.
         */
        @NonNull
        public IkeSessionParams build() {
            if (mSaProposalList.isEmpty()) {
                throw new IllegalArgumentException("IKE SA proposal not found");
            }
            if (mServerAddress == null
                    || mUdpEncapSocket == null
                    || mLocalIdentification == null
                    || mRemoteIdentification == null
                    || mLocalAuthConfig == null
                    || mRemoteAuthConfig == null) {
                throw new IllegalArgumentException("Necessary parameter missing.");
            }

            return new IkeSessionParams(
                    mServerAddress,
                    mUdpEncapSocket,
                    mSaProposalList.toArray(new IkeSaProposal[mSaProposalList.size()]),
                    mLocalIdentification,
                    mRemoteIdentification,
                    mLocalAuthConfig,
                    mRemoteAuthConfig,
                    mIsIkeFragmentationSupported);
        }

        // TODO: add methods for supporting IKE fragmentation.
    }
}
