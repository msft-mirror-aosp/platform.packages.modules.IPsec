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

import static android.net.ipsec.ike.IkeSessionOptions.IkeAuthConfig;
import static android.net.ipsec.ike.IkeSessionOptions.IkeAuthDigitalSignLocalConfig;
import static android.net.ipsec.ike.IkeSessionOptions.IkeAuthDigitalSignRemoteConfig;
import static android.net.ipsec.ike.IkeSessionOptions.IkeAuthEapConfig;
import static android.net.ipsec.ike.IkeSessionOptions.IkeAuthPskConfig;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.eap.EapSessionConfig;

import androidx.test.InstrumentationRegistry;

import com.android.internal.net.TestUtils;

import libcore.net.InetAddressUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

public final class IkeSessionOptionsTest {
    private static final String PSK_HEX_STRING = "6A756E69706572313233";
    private static final byte[] PSK = TestUtils.hexStringToByteArray(PSK_HEX_STRING);

    private static final Inet4Address LOCAL_IPV4_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.200"));
    private static final Inet4Address REMOTE_IPV4_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.100"));

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

    private void verifyIkeSessionOptionsCommon(IkeSessionOptions sessionOptions) {
        assertEquals(REMOTE_IPV4_ADDRESS, sessionOptions.getServerAddress());
        assertEquals(mUdpEncapSocket, sessionOptions.getUdpEncapsulationSocket());
        assertArrayEquals(new SaProposal[] {mIkeSaProposal}, sessionOptions.getSaProposals());

        assertEquals(mLocalIdentification, sessionOptions.getLocalIdentification());
        assertEquals(mRemoteIdentification, sessionOptions.getRemoteIdentification());

        assertFalse(sessionOptions.isIkeFragmentationSupported());
    }

    @Test
    public void testBuildWithPsk() throws Exception {
        IkeSessionOptions sessionOptions =
                new IkeSessionOptions.Builder()
                        .setServerAddress(REMOTE_IPV4_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthPsk(PSK)
                        .build();

        verifyIkeSessionOptionsCommon(sessionOptions);

        IkeAuthConfig localConfig = sessionOptions.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthPskConfig);
        assertEquals(IkeSessionOptions.IKE_AUTH_METHOD_PSK, localConfig.mAuthMethod);
        assertArrayEquals(PSK, ((IkeAuthPskConfig) localConfig).mPsk);

        IkeAuthConfig remoteConfig = sessionOptions.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthPskConfig);
        assertEquals(IkeSessionOptions.IKE_AUTH_METHOD_PSK, remoteConfig.mAuthMethod);
        assertArrayEquals(PSK, ((IkeAuthPskConfig) remoteConfig).mPsk);
    }

    @Test
    public void testBuildWithEap() throws Exception {
        EapSessionConfig eapConfig = mock(EapSessionConfig.class);

        IkeSessionOptions sessionOptions =
                new IkeSessionOptions.Builder()
                        .setServerAddress(REMOTE_IPV4_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthEap(mMockServerCaCert, eapConfig)
                        .build();

        verifyIkeSessionOptionsCommon(sessionOptions);

        IkeAuthConfig localConfig = sessionOptions.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthEapConfig);
        assertEquals(IkeSessionOptions.IKE_AUTH_METHOD_EAP, localConfig.mAuthMethod);
        assertEquals(eapConfig, ((IkeAuthEapConfig) localConfig).mEapConfig);

        IkeAuthConfig remoteConfig = sessionOptions.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthDigitalSignRemoteConfig);
        assertEquals(IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, remoteConfig.mAuthMethod);
        assertEquals(
                mMockServerCaCert,
                ((IkeAuthDigitalSignRemoteConfig) remoteConfig).mTrustAnchor.getTrustedCert());
    }

    @Test
    public void testBuildWithDigitalSignatureAuth() throws Exception {
        IkeSessionOptions sessionOptions =
                new IkeSessionOptions.Builder()
                        .setServerAddress(REMOTE_IPV4_ADDRESS)
                        .setUdpEncapsulationSocket(mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthDigitalSignature(
                                mMockServerCaCert, mMockClientEndCert, mMockRsaPrivateKey)
                        .build();

        verifyIkeSessionOptionsCommon(sessionOptions);

        IkeAuthConfig localConfig = sessionOptions.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthDigitalSignLocalConfig);

        IkeAuthDigitalSignLocalConfig localAuthConfig = (IkeAuthDigitalSignLocalConfig) localConfig;
        assertEquals(
                IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, localAuthConfig.mAuthMethod);
        assertEquals(mMockClientEndCert, localAuthConfig.mEndCert);
        assertTrue(localAuthConfig.mIntermediateCerts.isEmpty());
        assertEquals(mMockRsaPrivateKey, localAuthConfig.mPrivateKey);

        IkeAuthConfig remoteConfig = sessionOptions.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthDigitalSignRemoteConfig);
        assertEquals(IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE, remoteConfig.mAuthMethod);
        assertEquals(
                mMockServerCaCert,
                ((IkeAuthDigitalSignRemoteConfig) remoteConfig).mTrustAnchor.getTrustedCert());
    }

    @Test
    public void testBuildWithDsaDigitalSignatureAuth() throws Exception {
        try {
            IkeSessionOptions sessionOptions =
                    new IkeSessionOptions.Builder()
                            .setServerAddress(REMOTE_IPV4_ADDRESS)
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

    @Test
    public void testBuildWithoutSaProposal() throws Exception {
        try {
            new IkeSessionOptions.Builder()
                    .setServerAddress(REMOTE_IPV4_ADDRESS)
                    .setUdpEncapsulationSocket(mUdpEncapSocket)
                    .build();
            fail("Expected to fail due to absence of SA proposal.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testBuildWithoutLocalId() throws Exception {
        try {
            new IkeSessionOptions.Builder()
                    .setServerAddress(REMOTE_IPV4_ADDRESS)
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
            new IkeSessionOptions.Builder()
                    .setServerAddress(REMOTE_IPV4_ADDRESS)
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
}
