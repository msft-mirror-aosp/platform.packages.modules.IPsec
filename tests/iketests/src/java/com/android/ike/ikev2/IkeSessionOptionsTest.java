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

import static com.android.ike.ikev2.IkeSessionOptions.IkeAuthConfig;
import static com.android.ike.ikev2.IkeSessionOptions.IkeAuthDigitalSignRemoteConfig;
import static com.android.ike.ikev2.IkeSessionOptions.IkeAuthEapConfig;
import static com.android.ike.ikev2.IkeSessionOptions.IkeAuthPskConfig;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;

import androidx.test.InstrumentationRegistry;

import com.android.ike.TestUtils;
import com.android.ike.eap.EapSessionConfig;

import libcore.net.InetAddressUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.security.cert.X509Certificate;

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
                new IkeSessionOptions.Builder(REMOTE_IPV4_ADDRESS, mUdpEncapSocket)
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
        X509Certificate mockCert = mock(X509Certificate.class);
        EapSessionConfig eapConfig = mock(EapSessionConfig.class);

        IkeSessionOptions sessionOptions =
                new IkeSessionOptions.Builder(REMOTE_IPV4_ADDRESS, mUdpEncapSocket)
                        .addSaProposal(mIkeSaProposal)
                        .setLocalIdentification(mLocalIdentification)
                        .setRemoteIdentification(mRemoteIdentification)
                        .setAuthEap(mockCert, eapConfig)
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
                mockCert,
                ((IkeAuthDigitalSignRemoteConfig) remoteConfig).mTrustAnchor.getTrustedCert());
    }

    @Test
    public void testBuildWithoutSaProposal() throws Exception {
        try {
            new IkeSessionOptions.Builder(REMOTE_IPV4_ADDRESS, mUdpEncapSocket).build();
            fail("Expected to fail due to absence of SA proposal.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testBuildWithoutLocalId() throws Exception {
        try {
            new IkeSessionOptions.Builder(REMOTE_IPV4_ADDRESS, mUdpEncapSocket)
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
            new IkeSessionOptions.Builder(REMOTE_IPV4_ADDRESS, mUdpEncapSocket)
                    .addSaProposal(mIkeSaProposal)
                    .setLocalIdentification(mLocalIdentification)
                    .setRemoteIdentification(mRemoteIdentification)
                    .build();
            fail("Expected to fail because authentiction method is not set.");
        } catch (IllegalArgumentException expected) {
        }
    }
}
