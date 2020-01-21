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

package android.net.ipsec.test.ike;

import static android.net.ipsec.test.ike.IkeSessionParams.IKE_HARD_LIFETIME_SEC_DEFAULT;
import static android.net.ipsec.test.ike.IkeSessionParams.IKE_HARD_LIFETIME_SEC_MAXIMUM;
import static android.net.ipsec.test.ike.IkeSessionParams.IKE_HARD_LIFETIME_SEC_MINIMUM;
import static android.net.ipsec.test.ike.IkeSessionParams.IKE_SOFT_LIFETIME_SEC_DEFAULT;
import static android.net.ipsec.test.ike.IkeSessionParams.IkeAuthConfig;
import static android.net.ipsec.test.ike.IkeSessionParams.IkeAuthDigitalSignLocalConfig;
import static android.net.ipsec.test.ike.IkeSessionParams.IkeAuthDigitalSignRemoteConfig;
import static android.net.ipsec.test.ike.IkeSessionParams.IkeAuthEapConfig;
import static android.net.ipsec.test.ike.IkeSessionParams.IkeAuthPskConfig;
import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_IP4_PCSCF;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_IP6_PCSCF;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.net.eap.test.EapSessionConfig;
import android.util.SparseArray;

import androidx.test.InstrumentationRegistry;

import com.android.internal.net.test.TestUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.concurrent.TimeUnit;

public final class IkeSessionParamsTest {
    private static final String PSK_HEX_STRING = "6A756E69706572313233";
    private static final byte[] PSK = TestUtils.hexStringToByteArray(PSK_HEX_STRING);

    private static final String LOCAL_IPV4_HOST_ADDRESS = "192.0.2.100";
    private static final String REMOTE_IPV4_HOST_ADDRESS = "192.0.2.100";
    private static final String REMOTE_HOST_NAME = "server.test.android.net";

    private static final Inet4Address LOCAL_IPV4_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress(LOCAL_IPV4_HOST_ADDRESS));
    private static final Inet4Address REMOTE_IPV4_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress(REMOTE_IPV4_HOST_ADDRESS));

    private static final Inet4Address PCSCF_IPV4_ADDRESS_1 =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.1"));
    private static final Inet4Address PCSCF_IPV4_ADDRESS_2 =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.2"));
    private static final Inet6Address PCSCF_IPV6_ADDRESS_1 =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:DB8::1"));
    private static final Inet6Address PCSCF_IPV6_ADDRESS_2 =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:DB8::2"));

    private ConnectivityManager mMockConnectManager;
    private Network mMockDefaultNetwork;
    private Network mMockUserConfigNetwork;

    private UdpEncapsulationSocket mUdpEncapSocket;
    private IkeSaProposal mIkeSaProposal;
    private IkeIdentification mLocalIdentification;
    private IkeIdentification mRemoteIdentification;

    private X509Certificate mMockServerCaCert;
    private X509Certificate mMockClientEndCert;
    private PrivateKey mMockRsaPrivateKey;

    @Before
    public void setUp() throws Exception {
        Context context = InstrumentationRegistry.getContext();
        IpSecManager ipSecManager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
        mUdpEncapSocket = ipSecManager.openUdpEncapsulationSocket();

        mMockConnectManager = mock(ConnectivityManager.class);
        mMockDefaultNetwork = mock(Network.class);
        mMockUserConfigNetwork = mock(Network.class);
        when(mMockConnectManager.getActiveNetwork()).thenReturn(mMockDefaultNetwork);

        mIkeSaProposal =
                new IkeSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8,
                                SaProposal.KEY_LEN_AES_128)
                        .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();
        mLocalIdentification = new IkeIpv4AddrIdentification(LOCAL_IPV4_ADDRESS);
        mRemoteIdentification = new IkeIpv4AddrIdentification(REMOTE_IPV4_ADDRESS);

        mMockServerCaCert = mock(X509Certificate.class);
        mMockClientEndCert = mock(X509Certificate.class);
        mMockRsaPrivateKey = mock(RSAPrivateKey.class);
    }

    @After
    public void tearDown() throws Exception {
        mUdpEncapSocket.close();
    }

    private void verifyIkeSessionParamsWithSeverIpCommon(IkeSessionParams sessionParams) {
        assertEquals(REMOTE_IPV4_HOST_ADDRESS, sessionParams.getServerAddressInternal());
        verifyIkeSessionParamsCommon(sessionParams);
    }

    private void verifyIkeSessionParamsCommon(IkeSessionParams sessionParams) {
        assertArrayEquals(
                new SaProposal[] {mIkeSaProposal}, sessionParams.getSaProposalsInternal());

        assertEquals(mLocalIdentification, sessionParams.getLocalIdentification());
        assertEquals(mRemoteIdentification, sessionParams.getRemoteIdentification());

        assertFalse(sessionParams.isIkeFragmentationSupported());
    }

    private void verifyAuthPskConfig(IkeSessionParams sessionParams) {
        IkeAuthConfig localConfig = sessionParams.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthPskConfig);
        assertEquals(IkeSessionParams.IKE_AUTH_METHOD_PSK, localConfig.mAuthMethod);
        assertArrayEquals(PSK, ((IkeAuthPskConfig) localConfig).mPsk);

        IkeAuthConfig remoteConfig = sessionParams.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthPskConfig);
        assertEquals(IkeSessionParams.IKE_AUTH_METHOD_PSK, remoteConfig.mAuthMethod);
        assertArrayEquals(PSK, ((IkeAuthPskConfig) remoteConfig).mPsk);
    }

    @Test
    public void testBuildWithPsk() throws Exception {
        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthPsk(PSK)
                        .build();

        verifyIkeSessionParamsWithSeverIpCommon(sessionParams);
        verifyAuthPskConfig(sessionParams);

        assertEquals(mMockDefaultNetwork, sessionParams.getNetwork());

        assertEquals(IKE_HARD_LIFETIME_SEC_DEFAULT, sessionParams.getHardLifetime());
        assertEquals(IKE_SOFT_LIFETIME_SEC_DEFAULT, sessionParams.getSoftLifetime());
    }

    @Test
    public void testBuildWithPskAndLifetime() throws Exception {
        long hardLifetimeSec = TimeUnit.HOURS.toSeconds(20L);
        long softLifetimeSec = TimeUnit.HOURS.toSeconds(10L);

        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthPsk(PSK)
                        .setLifetime(hardLifetimeSec, softLifetimeSec)
                        .build();

        verifyIkeSessionParamsWithSeverIpCommon(sessionParams);
        verifyAuthPskConfig(sessionParams);

        assertEquals(hardLifetimeSec, sessionParams.getHardLifetime());
        assertEquals(softLifetimeSec, sessionParams.getSoftLifetime());
    }

    @Test
    public void testBuildWithPskAndHostname() throws Exception {
        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_HOST_NAME)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthPsk(PSK)
                        .build();

        verifyIkeSessionParamsCommon(sessionParams);
        verifyAuthPskConfig(sessionParams);

        assertEquals(REMOTE_HOST_NAME, sessionParams.getServerAddressInternal());
    }

    @Test
    public void testBuildWithEap() throws Exception {
        EapSessionConfig eapConfig = mock(EapSessionConfig.class);

        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthEap(mMockServerCaCert, eapConfig)
                        .build();

        verifyIkeSessionParamsWithSeverIpCommon(sessionParams);
        assertEquals(mMockDefaultNetwork, sessionParams.getNetwork());

        IkeAuthConfig localConfig = sessionParams.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthEapConfig);
        assertEquals(IkeSessionParams.IKE_AUTH_METHOD_EAP, localConfig.mAuthMethod);
        assertEquals(eapConfig, ((IkeAuthEapConfig) localConfig).mEapConfig);

        IkeAuthConfig remoteConfig = sessionParams.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthDigitalSignRemoteConfig);
        assertEquals(IkeSessionParams.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, remoteConfig.mAuthMethod);
        assertEquals(
                mMockServerCaCert,
                ((IkeAuthDigitalSignRemoteConfig) remoteConfig).mTrustAnchor.getTrustedCert());
    }

    @Test
    public void testBuildWithDigitalSignatureAuth() throws Exception {
        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                        .setNetwork(mMockUserConfigNetwork)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthDigitalSignature(
                                mMockServerCaCert, mMockClientEndCert, mMockRsaPrivateKey)
                        .build();

        verifyIkeSessionParamsWithSeverIpCommon(sessionParams);
        assertEquals(mMockUserConfigNetwork, sessionParams.getNetwork());

        IkeAuthConfig localConfig = sessionParams.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthDigitalSignLocalConfig);

        IkeAuthDigitalSignLocalConfig localAuthConfig = (IkeAuthDigitalSignLocalConfig) localConfig;
        assertEquals(
                IkeSessionParams.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, localAuthConfig.mAuthMethod);
        assertEquals(mMockClientEndCert, localAuthConfig.mEndCert);
        assertTrue(localAuthConfig.mIntermediateCerts.isEmpty());
        assertEquals(mMockRsaPrivateKey, localAuthConfig.mPrivateKey);

        IkeAuthConfig remoteConfig = sessionParams.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthDigitalSignRemoteConfig);
        assertEquals(IkeSessionParams.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, remoteConfig.mAuthMethod);
        assertEquals(
                mMockServerCaCert,
                ((IkeAuthDigitalSignRemoteConfig) remoteConfig).mTrustAnchor.getTrustedCert());
    }

    @Test
    public void testBuildWithDsaDigitalSignatureAuth() throws Exception {
        try {
            IkeSessionParams sessionParams =
                    new IkeSessionParams.Builder(mMockConnectManager)
                            .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                            .setUdpEncapsulationSocket(mUdpEncapSocket)
                            .addSaProposal(mIkeSaProposal)
                            .setLocalIdentification(mLocalIdentification)
                            .setRemoteIdentification(mRemoteIdentification)
                            .setAuthDigitalSignature(
                                    mMockServerCaCert,
                                    mMockClientEndCert,
                                    mock(DSAPrivateKey.class))
                            .build();
            fail("Expected to fail because DSA is not supported");
        } catch (IllegalArgumentException expected) {

        }
    }

    private void verifyAttrTypes(SparseArray expectedAttrCntMap, IkeSessionParams ikeParams) {
        ConfigAttribute[] configAttributes = ikeParams.getConfigurationAttributesInternal();

        SparseArray<Integer> atrrCntMap = expectedAttrCntMap.clone();

        for (int i = 0; i < configAttributes.length; i++) {
            int attType = configAttributes[i].attributeType;
            assertNotNull(atrrCntMap.get(attType));

            atrrCntMap.put(attType, atrrCntMap.get(attType) - 1);
            if (atrrCntMap.get(attType) == 0) atrrCntMap.remove(attType);
        }

        assertEquals(0, atrrCntMap.size());
    }

    @Test
    public void testBuildWithPcscfAddress() throws Exception {
        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthPsk(PSK)
                        .addPcscfServerRequest(AF_INET)
                        .addPcscfServerRequest(PCSCF_IPV4_ADDRESS_1)
                        .addPcscfServerRequest(PCSCF_IPV6_ADDRESS_2)
                        .addPcscfServerRequest(AF_INET6)
                        .addPcscfServerRequest(PCSCF_IPV4_ADDRESS_1)
                        .addPcscfServerRequest(PCSCF_IPV6_ADDRESS_2)
                        .build();

        SparseArray<Integer> expectedAttrCounts = new SparseArray<>();
        expectedAttrCounts.put(CONFIG_ATTR_IP4_PCSCF, 3);
        expectedAttrCounts.put(CONFIG_ATTR_IP6_PCSCF, 3);

        verifyAttrTypes(expectedAttrCounts, sessionParams);
    }

    @Test
    public void testBuildWithoutPcscfAddress() throws Exception {
        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(mMockConnectManager)
                        .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthPsk(PSK)
                        .build();

        SparseArray<Integer> expectedAttrCounts = new SparseArray<>();

        verifyAttrTypes(expectedAttrCounts, sessionParams);
    }

    @Test
    public void testBuildWithoutSaProposal() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                    .setUdpEncapsulationSocket(mUdpEncapSocket)
                    .build();
            fail("Expected to fail due to absence of SA proposal.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testBuildWithoutLocalId() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                    .setUdpEncapsulationSocket(mUdpEncapSocket)
                    .addSaProposal(mIkeSaProposal)
                    .setRemoteIdentification(mRemoteIdentification)
                    .setAuthPsk(PSK)
                    .build();
            fail("Expected to fail because local identification is not set.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testBuildWithoutSetAuth() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setServerAddress(REMOTE_IPV4_HOST_ADDRESS)
                    .setUdpEncapsulationSocket(mUdpEncapSocket)
                    .addSaProposal(mIkeSaProposal)
                    .setLocalIdentification(mLocalIdentification)
                    .setRemoteIdentification(mRemoteIdentification)
                    .build();
            fail("Expected to fail because authentiction method is not set.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testNonAsciiFqdnAuthentication() throws Exception {
        try {
            new IkeFqdnIdentification("¯\\_(ツ)_/¯");
            fail("Expected failure based on non-ASCII characters.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testSetHardLifetimeTooLong() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setLifetime(IKE_HARD_LIFETIME_SEC_MAXIMUM + 1, IKE_SOFT_LIFETIME_SEC_DEFAULT);
            fail("Expected failure because hard lifetime is too long");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testSetHardLifetimeTooShort() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setLifetime(IKE_HARD_LIFETIME_SEC_MINIMUM - 1, IKE_SOFT_LIFETIME_SEC_DEFAULT);
            fail("Expected failure because hard lifetime is too short");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testSetSoftLifetimeTooLong() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setLifetime(IKE_HARD_LIFETIME_SEC_DEFAULT, IKE_HARD_LIFETIME_SEC_DEFAULT);
            fail("Expected failure because soft lifetime is too long");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testSetSoftLifetimeTooShort() throws Exception {
        try {
            new IkeSessionParams.Builder(mMockConnectManager)
                    .setLifetime(IKE_HARD_LIFETIME_SEC_DEFAULT, 0L);
            fail("Expected failure because soft lifetime is too short");
        } catch (IllegalArgumentException expected) {
        }
    }
}
