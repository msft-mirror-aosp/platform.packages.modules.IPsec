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
 * IkeSessionOptions contains all user provided configurations for negotiating an IKE SA.
 *
 * <p>TODO: Make this doc more user-friendly.
 */
public final class IkeSessionOptions {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({IKE_AUTH_METHOD_PSK, IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, IKE_AUTH_METHOD_EAP})
    public @interface IkeAuthMethod {}

    // Constants to describe user configured authentication methods.
    public static final int IKE_AUTH_METHOD_PSK = 1;
    public static final int IKE_AUTH_METHOD_PUB_KEY_SIGNATURE = 2;
    public static final int IKE_AUTH_METHOD_EAP = 3;

    private final InetAddress mServerAddress;
    private final UdpEncapsulationSocket mUdpEncapSocket;
    private final IkeSaProposal[] mSaProposals;

    private final IkeIdentification mLocalIdentification;
    private final IkeIdentification mRemoteIdentification;

    private final IkeAuthConfig mLocalAuthConfig;
    private final IkeAuthConfig mRemoteAuthConfig;

    private final boolean mIsIkeFragmentationSupported;

    private IkeSessionOptions(
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

    public InetAddress getServerAddress() {
        return mServerAddress;
    }

    public UdpEncapsulationSocket getUdpEncapsulationSocket() {
        return mUdpEncapSocket;
    }

    public IkeSaProposal[] getSaProposals() {
        return mSaProposals;
    }

    public IkeIdentification getLocalIdentification() {
        return mLocalIdentification;
    }

    public IkeIdentification getRemoteIdentification() {
        return mRemoteIdentification;
    }

    public IkeAuthConfig getLocalAuthConfig() {
        return mLocalAuthConfig;
    }

    public IkeAuthConfig getRemoteAuthConfig() {
        return mRemoteAuthConfig;
    }

    public boolean isIkeFragmentationSupported() {
        return mIsIkeFragmentationSupported;
    }
    /** This class contains common information of an IKEv2 authentication configuration. */
    public abstract static class IkeAuthConfig {
        @IkeAuthMethod public final int mAuthMethod;

        protected IkeAuthConfig(@IkeAuthMethod int authMethod) {
            mAuthMethod = authMethod;
        }
    }

    /**
     * This class represents the configuration to support IKEv2 pre-shared-key-based authentication
     * of local or remote side.
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
     */
    public static class IkeAuthEapConfig extends IkeAuthConfig {
        public final EapSessionConfig mEapConfig;

        private IkeAuthEapConfig(EapSessionConfig eapConfig) {
            super(IKE_AUTH_METHOD_EAP);

            mEapConfig = eapConfig;
        }
    }

    /** This class can be used to incrementally construct a IkeSessionOptions. */
    public static final class Builder {
        private final List<IkeSaProposal> mSaProposalList = new LinkedList<>();

        private InetAddress mServerAddress;
        private UdpEncapsulationSocket mUdpEncapSocket;

        private IkeIdentification mLocalIdentification;
        private IkeIdentification mRemoteIdentification;

        private IkeAuthConfig mLocalAuthConfig;
        private IkeAuthConfig mRemoteAuthConfig;

        private boolean mIsIkeFragmentationSupported = false;

        /**
         * Sets server address
         *
         * @param serverAddress IP address of remote IKE server.
         * @return Builder this, to facilitate chaining.
         */
        public Builder setServerAddress(@NonNull InetAddress serverAddress) {
            mServerAddress = serverAddress;
            return this;
        }

        /**
         * Sets UDP-Encapsulated socket
         *
         * @param udpEncapsulationSocket {@link IpSecManager.UdpEncapsulationSocket} for sending and
         *     receiving IKE message.
         * @return Builder this, to facilitate chaining.
         */
        public Builder setUdpEncapsulationSocket(
                @NonNull UdpEncapsulationSocket udpEncapsulationSocket) {
            mUdpEncapSocket = udpEncapsulationSocket;
            return this;
        }

        /**
         * Sets local IKE identification.
         *
         * @param identification the local IKE identification.
         * @return Builder this, to facilitate chaining.
         */
        public Builder setLocalIdentification(IkeIdentification identification) {
            mLocalIdentification = identification;
            return this;
        }

        /**
         * Sets remote IKE identification.
         *
         * @param identification the remote IKE identification.
         * @return Builder this, to facilitate chaining.
         */
        public Builder setRemoteIdentification(IkeIdentification identification) {
            mRemoteIdentification = identification;
            return this;
        }

        /**
         * Adds an IKE SA proposal to IkeSessionOptions being built.
         *
         * @param proposal IKE SA proposal.
         * @return Builder this, to facilitate chaining.
         * @throws IllegalArgumentException if input proposal is not IKE SA proposal.
         */
        public Builder addSaProposal(IkeSaProposal proposal) {
            if (proposal.getProtocolId() != IkePayload.PROTOCOL_ID_IKE) {
                throw new IllegalArgumentException(
                        "Expected IKE SA Proposal but received Child SA proposal");
            }
            mSaProposalList.add(proposal);
            return this;
        }

        /**
         * Uses pre-shared key to do IKE authentication.
         *
         * <p>Both client and server MUST be authenticated using the provided shared key. IKE
         * authentication will fail if the remote peer tries to use other authentication methods.
         *
         * <p>Users MUST declare only one authentication method. Calling this function will override
         * the previously set authentication configuration.
         *
         * @param sharedKey the shared key.
         * @return Builder this, to facilitate chaining.
         */
        public Builder setAuthPsk(@NonNull byte[] sharedKey) {
            mLocalAuthConfig = new IkeAuthPskConfig(sharedKey);
            mRemoteAuthConfig = new IkeAuthPskConfig(sharedKey);
            return this;
        }

        /**
         * Uses EAP to do IKE authentication.
         *
         * <p>EAP are typically used to authenticate the IKE client to the server. It MUST be used
         * in conjunction with a public-key-signature-based authentication of the server to the
         * client.
         *
         * <p>Users MUST declare only one authentication method. Calling this function will override
         * the previously set authentication configuration.
         *
         * @see <a href="https://tools.ietf.org/html/rfc5280">RFC 5280, Internet X.509 Public Key
         *     Infrastructure Certificate and Certificate Revocation List (CRL) Profile</a>
         * @param serverCaCert the CA certificate for validating the received server certificate(s).
         * @return Builder this, to facilitate chaining.
         */
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
         * Uses certificate and digital signature to do IKE authentication.
         *
         * <p>The public key included by the client end certificate and the signature private key
         * MUST come from the same key pair.
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
         * Uses certificate and digital signature to do IKE authentication.
         *
         * <p>The public key included by the client end certificate and the signature private key
         * MUST come from the same key pair.
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
         * Validates, builds and returns the IkeSessionOptions
         *
         * @return IkeSessionOptions the validated IkeSessionOptions
         * @throws IllegalArgumentException if no IKE SA proposal is provided
         */
        public IkeSessionOptions build() {
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

            return new IkeSessionOptions(
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
