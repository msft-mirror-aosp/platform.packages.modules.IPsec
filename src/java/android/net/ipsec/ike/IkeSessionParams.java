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

import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.SystemApi;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.eap.EapSessionConfig;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Pcscf;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Pcscf;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.IkeConfigAttribute;
import com.android.internal.net.ipsec.ike.message.IkePayload;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

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

    /** @hide */
    @VisibleForTesting
    static final long IKE_HARD_LIFETIME_SEC_MINIMUM = TimeUnit.MINUTES.toSeconds(5L);
    /** @hide */
    @VisibleForTesting
    static final long IKE_HARD_LIFETIME_SEC_MAXIMUM = TimeUnit.HOURS.toSeconds(24L);
    /** @hide */
    @VisibleForTesting
    static final long IKE_HARD_LIFETIME_SEC_DEFAULT = TimeUnit.HOURS.toSeconds(4L);

    /** @hide */
    @VisibleForTesting
    static final long IKE_SOFT_LIFETIME_SEC_MINIMUM = TimeUnit.MINUTES.toSeconds(2L);
    /** @hide */
    @VisibleForTesting
    static final long IKE_SOFT_LIFETIME_SEC_DEFAULT = TimeUnit.HOURS.toSeconds(2L);

    /** @hide */
    @VisibleForTesting
    static final long IKE_LIFETIME_MARGIN_SEC_MINIMUM = TimeUnit.MINUTES.toSeconds(1L);

    @NonNull private final InetAddress mServerAddress;
    @NonNull private final UdpEncapsulationSocket mUdpEncapSocket;
    @NonNull private final IkeSaProposal[] mSaProposals;

    @NonNull private final IkeIdentification mLocalIdentification;
    @NonNull private final IkeIdentification mRemoteIdentification;

    @NonNull private final IkeAuthConfig mLocalAuthConfig;
    @NonNull private final IkeAuthConfig mRemoteAuthConfig;

    @NonNull private final IkeConfigAttribute[] mConfigRequests;

    private final long mHardLifetimeSec;
    private final long mSoftLifetimeSec;

    private final boolean mIsIkeFragmentationSupported;

    private IkeSessionParams(
            @NonNull InetAddress serverAddress,
            @NonNull UdpEncapsulationSocket udpEncapsulationSocket,
            @NonNull IkeSaProposal[] proposals,
            @NonNull IkeIdentification localIdentification,
            @NonNull IkeIdentification remoteIdentification,
            @NonNull IkeAuthConfig localAuthConfig,
            @NonNull IkeAuthConfig remoteAuthConfig,
            @NonNull IkeConfigAttribute[] configRequests,
            long hardLifetimeSec,
            long softLifetimeSec,
            boolean isIkeFragmentationSupported) {
        mServerAddress = serverAddress;
        mUdpEncapSocket = udpEncapsulationSocket;
        mSaProposals = proposals;

        mLocalIdentification = localIdentification;
        mRemoteIdentification = remoteIdentification;

        mLocalAuthConfig = localAuthConfig;
        mRemoteAuthConfig = remoteAuthConfig;

        mConfigRequests = configRequests;

        mHardLifetimeSec = hardLifetimeSec;
        mSoftLifetimeSec = softLifetimeSec;

        mIsIkeFragmentationSupported = isIkeFragmentationSupported;
    }

    /** Retrieves the configured server address */
    @NonNull
    public InetAddress getServerAddress() {
        return mServerAddress;
    }

    /** Retrieves the UDP encapsulation socket */
    @NonNull
    public UdpEncapsulationSocket getUdpEncapsulationSocket() {
        return mUdpEncapSocket;
    }

    /** Retrieves all ChildSaProposals configured */
    @NonNull
    public List<IkeSaProposal> getSaProposals() {
        return Arrays.asList(mSaProposals);
    }

    /** @hide */
    public IkeSaProposal[] getSaProposalsInternal() {
        return mSaProposals;
    }

    /** Retrieves the local (client) identity */
    @NonNull
    public IkeIdentification getLocalIdentification() {
        return mLocalIdentification;
    }

    /** Retrieves the required remote (server) identity */
    @NonNull
    public IkeIdentification getRemoteIdentification() {
        return mRemoteIdentification;
    }

    /** Retrieves the local (client) authentication configuration */
    @NonNull
    public IkeAuthConfig getLocalAuthConfig() {
        return mLocalAuthConfig;
    }

    /** Retrieves the remote (server) authentication configuration */
    @NonNull
    public IkeAuthConfig getRemoteAuthConfig() {
        return mRemoteAuthConfig;
    }

    /** Retrieves hard lifetime in seconds */
    public long getHardLifetime() {
        return mHardLifetimeSec;
    }

    /** Retrieves soft lifetime in seconds */
    public long getSoftLifetime() {
        return mSoftLifetimeSec;
    }

    /** @hide */
    public long getHardLifetimeMsInternal() {
        return TimeUnit.SECONDS.toMillis(mHardLifetimeSec);
    }

    /** @hide */
    public long getSoftLifetimeMsInternal() {
        return TimeUnit.SECONDS.toMillis(mSoftLifetimeSec);
    }

    /** @hide */
    public boolean isIkeFragmentationSupported() {
        return mIsIkeFragmentationSupported;
    }

    /** @hide */
    public IkeConfigAttribute[] getConfigurationAttributesInternal() {
        return mConfigRequests;
    }

    /** Retrieves the list of Configuration Requests @hide */
    @NonNull
    public List<IkeConfigRequest> getConfigurationRequests() {
        return Collections.unmodifiableList(Arrays.asList(mConfigRequests));
    }

    /** Represents an IKE session configuration request type @hide */
    public interface IkeConfigRequest {}

    /** Represents an IPv4 P_CSCF request @hide */
    public interface ConfigRequestIpv4PcscfServer extends IkeConfigRequest {
        /**
         * Retrieves the requested IPv4 P_CSCF server address
         *
         * @return The requested P_CSCF server address, or null if no specific P_CSCF server was
         *     requested
         */
        @Nullable
        Inet4Address getAddress();
    }

    /** Represents an IPv6 P_CSCF request @hide */
    public interface ConfigRequestIpv6PcscfServer extends IkeConfigRequest {
        /**
         * Retrieves the requested IPv6 P_CSCF server address
         *
         * @return The requested P_CSCF server address, or null if no specific P_CSCF server was
         *     requested
         */
        @Nullable
        Inet6Address getAddress();
    }

    /**
     * This class contains common information of an IKEv2 authentication configuration.
     */
    public abstract static class IkeAuthConfig {
        /** @hide */
        @IkeAuthMethod public final int mAuthMethod;

        /** @hide */
        IkeAuthConfig(@IkeAuthMethod int authMethod) {
            mAuthMethod = authMethod;
        }
    }

    /**
     * This class represents the configuration to support IKEv2 pre-shared-key-based authentication
     * of local or remote side.
     */
    public static class IkeAuthPskConfig extends IkeAuthConfig {
        /** @hide */
        @NonNull public final byte[] mPsk;

        private IkeAuthPskConfig(byte[] psk) {
            super(IKE_AUTH_METHOD_PSK);
            mPsk = psk;
        }

        /** Retrieves the pre-shared key */
        @NonNull
        public byte[] getPsk() {
            return Arrays.copyOf(mPsk, mPsk.length);
        }
    }

    /**
     * This class represents the configuration to support IKEv2 public-key-signature-based
     * authentication of the remote side.
     */
    public static class IkeAuthDigitalSignRemoteConfig extends IkeAuthConfig {
        /** @hide */
        @Nullable public final TrustAnchor mTrustAnchor;

        /**
         * If a certificate is provided, it MUST be the root CA used by the remote (server), or
         * authentication will fail. If no certificate is provided, any root CA in the system's
         * truststore is considered acceptable.
         */
        private IkeAuthDigitalSignRemoteConfig(@Nullable X509Certificate caCert) {
            super(IKE_AUTH_METHOD_PUB_KEY_SIGNATURE);
            if (caCert == null) {
                mTrustAnchor = null;
            } else {
                // The name constraints extension, defined in RFC 5280, indicates a name space
                // within which all subject names in subsequent certificates in a certification path
                // MUST be located.
                mTrustAnchor = new TrustAnchor(caCert, null /*nameConstraints*/);

                // TODO: Investigate if we need to support the name constraints extension.
            }
        }

        /** Retrieves the provided CA certificate for validating the remote certificate(s) */
        @Nullable
        public X509Certificate getRemoteCaCert() {
            if (mTrustAnchor == null) return null;
            return mTrustAnchor.getTrustedCert();
        }
    }

    /**
     * This class represents the configuration to support IKEv2 public-key-signature-based
     * authentication of the local side.
     */
    public static class IkeAuthDigitalSignLocalConfig extends IkeAuthConfig {
        /** @hide */
        @NonNull public final X509Certificate mEndCert;

        /** @hide */
        @NonNull public final List<X509Certificate> mIntermediateCerts;

        /** @hide */
        @NonNull public final PrivateKey mPrivateKey;

        private IkeAuthDigitalSignLocalConfig(
                @NonNull X509Certificate clientEndCert,
                @NonNull List<X509Certificate> clientIntermediateCerts,
                @NonNull PrivateKey privateKey) {
            super(IKE_AUTH_METHOD_PUB_KEY_SIGNATURE);
            mEndCert = clientEndCert;
            mIntermediateCerts = clientIntermediateCerts;
            mPrivateKey = privateKey;
        }

        /** Retrieves the client end certificate */
        @NonNull
        public X509Certificate getClientEndCertificate() {
            return mEndCert;
        }

        /** Retrieves the intermediate certificates */
        @NonNull
        public List<X509Certificate> getIntermediateCertificates() {
            return mIntermediateCerts;
        }

        /** Retrieves the private key */
        @NonNull
        public PrivateKey getPrivateKey() {
            return mPrivateKey;
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
        /** @hide */
        @NonNull public final EapSessionConfig mEapConfig;

        private IkeAuthEapConfig(EapSessionConfig eapConfig) {
            super(IKE_AUTH_METHOD_EAP);

            mEapConfig = eapConfig;
        }

        /** Retrieves EAP configuration */
        @NonNull
        public EapSessionConfig getEapConfig() {
            return mEapConfig;
        }
    }

    /** This class can be used to incrementally construct a {@link IkeSessionParams}. */
    public static final class Builder {
        @NonNull private final List<IkeSaProposal> mSaProposalList = new LinkedList<>();
        @NonNull private final List<IkeConfigAttribute> mConfigRequestList = new ArrayList<>();

        @Nullable private InetAddress mServerAddress;
        @Nullable private UdpEncapsulationSocket mUdpEncapSocket;

        @Nullable private IkeIdentification mLocalIdentification;
        @Nullable private IkeIdentification mRemoteIdentification;

        @Nullable private IkeAuthConfig mLocalAuthConfig;
        @Nullable private IkeAuthConfig mRemoteAuthConfig;

        private long mHardLifetimeSec = IKE_HARD_LIFETIME_SEC_DEFAULT;
        private long mSoftLifetimeSec = IKE_SOFT_LIFETIME_SEC_DEFAULT;

        private boolean mIsIkeFragmentationSupported = false;

        /**
         * Sets the server address for the {@link IkeSessionParams} being built.
         *
         * @param serverAddress the IP address of the IKE server.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setServerAddress(@NonNull InetAddress serverAddress) {
            if (serverAddress == null) {
                throw new NullPointerException("Required argument not provided");
            }

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
            if (udpEncapsulationSocket == null) {
                throw new NullPointerException("Required argument not provided");
            }

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
            if (identification == null) {
                throw new NullPointerException("Required argument not provided");
            }

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
            if (identification == null) {
                throw new NullPointerException("Required argument not provided");
            }

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
            if (proposal == null) {
                throw new NullPointerException("Required argument not provided");
            }

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
            if (sharedKey == null) {
                throw new NullPointerException("Required argument not provided");
            }

            mLocalAuthConfig = new IkeAuthPskConfig(sharedKey);
            mRemoteAuthConfig = new IkeAuthPskConfig(sharedKey);
            return this;
        }

        /**
         * Configures the {@link IkeSession} to use EAP authentication.
         *
         * <p>Not all EAP methods provide mutual authentication. As such EAP MUST be used in
         * conjunction with a public-key-signature-based authentication of the remote side.
         *
         * <p>Callers MUST declare only one authentication method. Calling this function will
         * override the previously set authentication configuration.
         *
         * @see <a href="https://tools.ietf.org/html/rfc5280">RFC 5280, Internet X.509 Public Key
         *     Infrastructure Certificate and Certificate Revocation List (CRL) Profile</a>
         * @see <a href="https://tools.ietf.org/html/rfc5998">RFC 5998, An Extension for EAP-Only
         *     Authentication in IKEv2
         * @param serverCaCert the CA certificate for validating the received server certificate(s).
         *     If a certificate is provided, it MUST be the root CA used by the server, or
         *     authentication will fail. If no certificate is provided, any root CA in the system's
         *     truststore is considered acceptable.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setAuthEap(
                @Nullable X509Certificate serverCaCert, @NonNull EapSessionConfig eapConfig) {
            if (eapConfig == null) {
                throw new NullPointerException("Required argument not provided");
            }

            mLocalAuthConfig = new IkeAuthEapConfig(eapConfig);
            mRemoteAuthConfig = new IkeAuthDigitalSignRemoteConfig(serverCaCert);

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
         *     If a certificate is provided, it MUST be the root CA used by the server, or
         *     authentication will fail. If no certificate is provided, any root CA in the system's
         *     truststore is considered acceptable.
         * @param clientEndCert the end certificate for remote server to verify the locally
         *     generated signature.
         * @param clientPrivateKey private key to generate outbound digital signature. Only {@link
         *     RSAPrivateKey} is supported.
         * @return Builder this, to facilitate chaining.
         */
        @NonNull
        public Builder setAuthDigitalSignature(
                @Nullable X509Certificate serverCaCert,
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
         *     If a null value is provided, IKE library will try all default CA certificates stored
         *     in Android system to do the validation. Otherwise, it will only use the provided CA
         *     certificate.
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
                @Nullable X509Certificate serverCaCert,
                @NonNull X509Certificate clientEndCert,
                @NonNull List<X509Certificate> clientIntermediateCerts,
                @NonNull PrivateKey clientPrivateKey) {
            if (clientEndCert == null
                    || clientIntermediateCerts == null
                    || clientPrivateKey == null) {
                throw new NullPointerException("Required argument not provided");
            }

            if (!(clientPrivateKey instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Unsupported private key type");
            }

            mLocalAuthConfig =
                    new IkeAuthDigitalSignLocalConfig(
                            clientEndCert, clientIntermediateCerts, clientPrivateKey);
            mRemoteAuthConfig = new IkeAuthDigitalSignRemoteConfig(serverCaCert);

            return this;
        }

        /**
         * Adds a specific internal P_CSCF server request to the {@link IkeSessionParams} being
         * built.
         *
         * @param address the requested P_CSCF address.
         * @return Builder this, to facilitate chaining.
         *
         * @hide
         */
        @NonNull
        public Builder addPcscfServerRequest(@NonNull InetAddress address) {
            if (address == null) {
                throw new NullPointerException("Required argument not provided");
            }

            if (address instanceof Inet4Address) {
                mConfigRequestList.add(new ConfigAttributeIpv4Pcscf((Inet4Address) address));
            } else if (address instanceof Inet6Address) {
                mConfigRequestList.add(new ConfigAttributeIpv6Pcscf((Inet6Address) address));
            } else {
                throw new IllegalArgumentException("Invalid address family");
            }
            return this;
        }

        /**
         * Adds a internal P_CSCF server request to the {@link IkeSessionParams} being built.
         *
         * @param addressFamily the address family. Only {@link OsConstants.AF_INET} and {@link
         *     OsConstants.AF_INET6} are allowed.
         * @return Builder this, to facilitate chaining.
         *
         * @hide
         */
        @NonNull
        public Builder addPcscfServerRequest(int addressFamily) {
            if (addressFamily == AF_INET) {
                mConfigRequestList.add(new ConfigAttributeIpv4Pcscf());
                return this;
            } else if (addressFamily == AF_INET6) {
                mConfigRequestList.add(new ConfigAttributeIpv6Pcscf());
                return this;
            } else {
                throw new IllegalArgumentException("Invalid address family: " + addressFamily);
            }
        }

        /**
         * Sets hard and soft lifetimes.
         *
         * <p>Lifetimes will not be negotiated with the remote IKE server.
         *
         * @param hardLifetimeSec number of seconds after which IKE SA will expire. Defaults to
         *     14400 seconds (4 hours). MUST be a value from 300 seconds (5 minutes) to 86400
         *     seconds (24 hours), inclusive.
         * @param softLifetimeSec number of seconds after which IKE SA will request rekey. Defaults
         *     to 7200 seconds (2 hours). MUST be at least 120 seconds (2 minutes), and at least 60
         *     seconds (1 minute) shorter than the hard lifetime.
         */
        @NonNull
        public Builder setLifetime(long hardLifetimeSec, long softLifetimeSec) {
            if (hardLifetimeSec < IKE_HARD_LIFETIME_SEC_MINIMUM
                    || hardLifetimeSec > IKE_HARD_LIFETIME_SEC_MAXIMUM
                    || softLifetimeSec < IKE_SOFT_LIFETIME_SEC_MINIMUM
                    || hardLifetimeSec - softLifetimeSec < IKE_LIFETIME_MARGIN_SEC_MINIMUM) {
                throw new IllegalArgumentException("Invalid lifetime value");
            }

            mHardLifetimeSec = hardLifetimeSec;
            mSoftLifetimeSec = softLifetimeSec;
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
                    mSaProposalList.toArray(new IkeSaProposal[0]),
                    mLocalIdentification,
                    mRemoteIdentification,
                    mLocalAuthConfig,
                    mRemoteAuthConfig,
                    mConfigRequestList.toArray(new IkeConfigAttribute[0]),
                    mHardLifetimeSec,
                    mSoftLifetimeSec,
                    mIsIkeFragmentationSupported);
        }

        // TODO: add methods for supporting IKE fragmentation.
    }
}
