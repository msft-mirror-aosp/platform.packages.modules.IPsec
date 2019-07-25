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

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.net.IpSecManager.UdpEncapsulationSocket;

import com.android.ike.ikev2.message.IkePayload;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.InetAddress;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
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

    // Package private constants to describe user configured authentication methods.
    static final int IKE_AUTH_METHOD_PSK = 1;
    static final int IKE_AUTH_METHOD_PUB_KEY_SIGNATURE = 2;
    static final int IKE_AUTH_METHOD_EAP = 3;

    private final InetAddress mServerAddress;
    private final UdpEncapsulationSocket mUdpEncapSocket;
    private final SaProposal[] mSaProposals;

    private final IkeIdentification mLocalIdentification;
    private final IkeIdentification mRemoteIdentification;

    private final IkeAuthConfig mLocalAuthConfig;
    private final IkeAuthConfig mRemoteAuthConfig;

    private final boolean mIsIkeFragmentationSupported;

    private IkeSessionOptions(
            InetAddress serverAddress,
            UdpEncapsulationSocket udpEncapsulationSocket,
            SaProposal[] proposals,
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

    /** Package private */
    InetAddress getServerAddress() {
        return mServerAddress;
    }
    /** Package private */
    UdpEncapsulationSocket getUdpEncapsulationSocket() {
        return mUdpEncapSocket;
    }
    /** Package private */
    SaProposal[] getSaProposals() {
        return mSaProposals;
    }
    /** Package private */
    IkeIdentification getLocalIdentification() {
        return mLocalIdentification;
    }
    /** Package private */
    IkeIdentification getRemoteIdentification() {
        return mRemoteIdentification;
    }
    /** Package private */
    IkeAuthConfig getLocalAuthConfig() {
        return mLocalAuthConfig;
    }
    /** Package private */
    IkeAuthConfig getRemoteAuthConfig() {
        return mRemoteAuthConfig;
    }
    /** Package private */
    boolean isIkeFragmentationSupported() {
        return mIsIkeFragmentationSupported;
    }
    /**
     * Package private class that contains common information of an IKEv2 authentication
     * configuration.
     */
    abstract static class IkeAuthConfig {
        @IkeAuthMethod final int mAuthMethod;

        protected IkeAuthConfig(@IkeAuthMethod int authMethod) {
            mAuthMethod = authMethod;
        }
    }

    /**
     * Package private class that contains configuration to do IKEv2 pre-shared-key-based
     * authentication of local or remote side.
     */
    static class IkeAuthPskConfig extends IkeAuthConfig {
        final byte[] mPsk;

        private IkeAuthPskConfig(byte[] psk) {
            super(IKE_AUTH_METHOD_PSK);
            mPsk = psk;
        }
    }

    /**
     * Package private class that contains configuration to do IKEv2 public-key-based authentication
     * of the remote side.
     */
    static class IkeAuthDigitalSignRemoteConfig extends IkeAuthConfig {
        final TrustAnchor mTrustAnchor;

        private IkeAuthDigitalSignRemoteConfig(TrustAnchor trustAnchor) {
            super(IKE_AUTH_METHOD_PUB_KEY_SIGNATURE);
            mTrustAnchor = trustAnchor;
        }
    }

    // TODO: Create IkeAuthDigitalSignLocalConfig to store signature hash algorithm and
    // certificates to do authentication of local side to the remote.

    /**
     * Package private class that contains configuration to do EAP authentication of the local side.
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
    static class IkeAuthEapConfig extends IkeAuthConfig {
        // TODO: Store EAP configuration

        private IkeAuthEapConfig() {
            super(IKE_AUTH_METHOD_EAP);
        }
    }

    /** This class can be used to incrementally construct a IkeSessionOptions. */
    public static final class Builder {
        private final InetAddress mServerAddress;
        private final UdpEncapsulationSocket mUdpEncapSocket;
        private final List<SaProposal> mSaProposalList = new LinkedList<>();

        private IkeIdentification mLocalIdentification;
        private IkeIdentification mRemoteIdentification;

        private IkeAuthConfig mLocalAuthConfig;
        private IkeAuthConfig mRemoteAuthConfig;

        private boolean mIsIkeFragmentationSupported = false;

        /**
         * Returns a new Builder for an IkeSessionOptions.
         *
         * @param serverAddress IP address of remote IKE server.
         * @param udpEncapsulationSocket {@link IpSecManager.UdpEncapsulationSocket} for sending and
         *     receiving IKE message.
         * @return Builder for an IkeSessionOptions.
         */
        public Builder(InetAddress serverAddress, UdpEncapsulationSocket udpEncapsulationSocket) {
            mServerAddress = serverAddress;
            mUdpEncapSocket = udpEncapsulationSocket;
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
        public Builder addSaProposal(SaProposal proposal) {
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
         * <p>TODO: Add input to take EAP configucations.
         *
         * <p>TODO: Investigate if we need to support the name constraints extension.
         *
         * @see <a href="https://tools.ietf.org/html/rfc5280">RFC 5280, Internet X.509 Public Key
         *     Infrastructure Certificate and Certificate Revocation List (CRL) Profile</a>
         * @param caCert the CA certificate for validating the received server certificate(s).
         * @return Builder this, to facilitate chaining.
         */
        public Builder setAuthEap(@NonNull X509Certificate caCert) {
            mLocalAuthConfig = new IkeAuthEapConfig();

            // The name constraints extension, defined in RFC 5280, indicates a name space within
            // which all subject names in subsequent certificates in a certification path MUST be
            // located.
            mRemoteAuthConfig =
                    new IkeAuthDigitalSignRemoteConfig(
                            new TrustAnchor(caCert, null /*nameConstraints*/));
            return this;
        }

        // TODO: Add methods to set authentication method to public key signature and EAP.

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
            if (mLocalIdentification == null
                    || mRemoteIdentification == null
                    || mLocalAuthConfig == null
                    || mRemoteAuthConfig == null) {
                throw new IllegalArgumentException(
                        "IKE identification or IKE authentication method is not set.");
            }

            return new IkeSessionOptions(
                    mServerAddress,
                    mUdpEncapSocket,
                    mSaProposalList.toArray(new SaProposal[mSaProposalList.size()]),
                    mLocalIdentification,
                    mRemoteIdentification,
                    mLocalAuthConfig,
                    mRemoteAuthConfig,
                    mIsIkeFragmentationSupported);
        }

        // TODO: add methods for supporting IKE fragmentation.
    }
}
