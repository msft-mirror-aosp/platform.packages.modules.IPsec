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

import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_1024_BIT_MODP;
import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_1536_BIT_MODP;
import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_2048_BIT_MODP;
import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_3072_BIT_MODP;
import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_4096_BIT_MODP;
import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_CURVE_25519;
import static android.net.ipsec.test.ike.SaProposal.DH_GROUP_NONE;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_3DES;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_AES_CBC;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_AES_CTR;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8;
import static android.net.ipsec.test.ike.SaProposal.ENCRYPTION_ALGORITHM_CHACHA20_POLY1305;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_AES_CMAC_96;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_384_192;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_512_256;
import static android.net.ipsec.test.ike.SaProposal.INTEGRITY_ALGORITHM_NONE;
import static android.net.ipsec.test.ike.SaProposal.KEY_LEN_AES_128;
import static android.net.ipsec.test.ike.SaProposal.KEY_LEN_UNUSED;
import static android.net.ipsec.test.ike.SaProposal.PSEUDORANDOM_FUNCTION_AES128_CMAC;
import static android.net.ipsec.test.ike.SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC;
import static android.net.ipsec.test.ike.SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1;
import static android.net.ipsec.test.ike.SaProposal.PSEUDORANDOM_FUNCTION_SHA2_256;
import static android.net.ipsec.test.ike.SaProposal.PSEUDORANDOM_FUNCTION_SHA2_384;
import static android.net.ipsec.test.ike.SaProposal.PSEUDORANDOM_FUNCTION_SHA2_512;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import android.net.IpSecAlgorithm;
import android.os.PersistableBundle;

import com.android.internal.net.ipsec.test.ike.crypto.IkeCipher;
import com.android.internal.net.ipsec.test.ike.crypto.IkeMacIntegrity;
import com.android.internal.net.ipsec.test.ike.message.IkePayload;
import com.android.internal.net.ipsec.test.ike.message.IkeSaPayload.DhGroupTransform;
import com.android.internal.net.ipsec.test.ike.message.IkeSaPayload.EncryptionTransform;
import com.android.internal.net.ipsec.test.ike.message.IkeSaPayload.IntegrityTransform;
import com.android.internal.net.ipsec.test.ike.message.IkeSaPayload.PrfTransform;
import com.android.internal.net.ipsec.test.ike.message.IkeSaPayload.Transform;
import com.android.internal.net.utils.test.build.SdkLevel;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public final class SaProposalTest {
    private final EncryptionTransform mEncryption3DesTransform;
    private final EncryptionTransform mEncryptionAesCbcTransform;
    private final EncryptionTransform mEncryptionAesGcm8Transform;
    private final EncryptionTransform mEncryptionAesGcm12Transform;
    private final IntegrityTransform mIntegrityHmacSha1Transform;
    private final IntegrityTransform mIntegrityNoneTransform;
    private final PrfTransform mPrfAes128XCbcTransform;
    private final DhGroupTransform mDhGroup1024Transform;

    private static final Set<Integer> SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S;
    private static final Set<Integer> SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S;

    static {
        SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S = new HashSet<>();
        SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S.add(ENCRYPTION_ALGORITHM_AES_CBC);
        SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S.add(ENCRYPTION_ALGORITHM_AES_GCM_8);
        SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S.add(ENCRYPTION_ALGORITHM_AES_GCM_12);
        SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S.add(ENCRYPTION_ALGORITHM_AES_GCM_16);

        SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S = new HashSet<>();
        SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S.add(INTEGRITY_ALGORITHM_NONE);
        SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S.add(INTEGRITY_ALGORITHM_HMAC_SHA1_96);
        SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S.add(INTEGRITY_ALGORITHM_HMAC_SHA2_256_128);
        SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S.add(INTEGRITY_ALGORITHM_HMAC_SHA2_384_192);
        SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S.add(INTEGRITY_ALGORITHM_HMAC_SHA2_512_256);
    }

    // For all crypto algorithms, private use range starts from 1024
    private static final int ALGORITHM_ID_INVALID = 1024;

    public SaProposalTest() {
        mEncryption3DesTransform =
                new EncryptionTransform(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED);
        mEncryptionAesCbcTransform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128);
        mEncryptionAesGcm8Transform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8, SaProposal.KEY_LEN_AES_128);
        mEncryptionAesGcm12Transform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12, SaProposal.KEY_LEN_AES_128);
        mIntegrityHmacSha1Transform =
                new IntegrityTransform(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96);
        mIntegrityNoneTransform = new IntegrityTransform(SaProposal.INTEGRITY_ALGORITHM_NONE);
        mPrfAes128XCbcTransform = new PrfTransform(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC);
        mDhGroup1024Transform = new DhGroupTransform(SaProposal.DH_GROUP_1024_BIT_MODP);
    }

    @Test
    public void testBuildIkeSaProposalWithNormalModeCipher() throws Exception {
        IkeSaProposal proposal =
                new IkeSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                        .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        assertEquals(IkePayload.PROTOCOL_ID_IKE, proposal.getProtocolId());
        assertArrayEquals(
                new EncryptionTransform[] {mEncryption3DesTransform},
                proposal.getEncryptionTransforms());
        assertArrayEquals(
                new IntegrityTransform[] {mIntegrityHmacSha1Transform},
                proposal.getIntegrityTransforms());
        assertArrayEquals(
                new PrfTransform[] {mPrfAes128XCbcTransform}, proposal.getPrfTransforms());
        assertArrayEquals(
                new DhGroupTransform[] {mDhGroup1024Transform}, proposal.getDhGroupTransforms());
    }

    @Test
    public void testBuildIkeSaProposalWithCombinedModeCipher() throws Exception {
        IkeSaProposal proposal =
                new IkeSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8,
                                SaProposal.KEY_LEN_AES_128)
                        .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        assertEquals(IkePayload.PROTOCOL_ID_IKE, proposal.getProtocolId());
        assertArrayEquals(
                new EncryptionTransform[] {mEncryptionAesGcm8Transform},
                proposal.getEncryptionTransforms());
        assertArrayEquals(
                new PrfTransform[] {mPrfAes128XCbcTransform}, proposal.getPrfTransforms());
        assertArrayEquals(
                new DhGroupTransform[] {mDhGroup1024Transform}, proposal.getDhGroupTransforms());
        assertTrue(proposal.getIntegrityTransforms().length == 0);
    }

    @Test
    public void testBuildChildSaProposalWithNormalCipher() throws Exception {
        ChildSaProposal proposal =
                new ChildSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, KEY_LEN_AES_128)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_NONE)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        assertEquals(IkePayload.PROTOCOL_ID_ESP, proposal.getProtocolId());
        assertArrayEquals(
                new EncryptionTransform[] {mEncryptionAesCbcTransform},
                proposal.getEncryptionTransforms());
        assertArrayEquals(
                new IntegrityTransform[] {mIntegrityNoneTransform},
                proposal.getIntegrityTransforms());
        assertArrayEquals(
                new DhGroupTransform[] {mDhGroup1024Transform}, proposal.getDhGroupTransforms());
    }

    private static void verifyPersistableBundleEncodeDecodeIsLossless(SaProposal proposal) {
        PersistableBundle bundle = proposal.toPersistableBundle();
        SaProposal resultProposal = SaProposal.fromPersistableBundle(bundle);

        assertEquals(proposal, resultProposal);
    }

    @Test
    public void testPersistableBundleEncodeDecodeIsLosslessChildProposal() throws Exception {
        ChildSaProposal proposal =
                new ChildSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, KEY_LEN_AES_128)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_NONE)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        verifyPersistableBundleEncodeDecodeIsLossless(proposal);
    }

    @Test
    public void testPersistableBundleEncodeDecodeIsLosslessIkeProposal() throws Exception {
        IkeSaProposal proposal =
                new IkeSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                        .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        verifyPersistableBundleEncodeDecodeIsLossless(proposal);
    }

    @Test
    public void testGetCopyWithoutDhGroup() throws Exception {
        ChildSaProposal proposal =
                new ChildSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, KEY_LEN_AES_128)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_NONE)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();
        ChildSaProposal proposalWithoutDh = proposal.getCopyWithoutDhTransform();

        assertArrayEquals(
                proposal.getEncryptionTransforms(), proposalWithoutDh.getEncryptionTransforms());
        assertArrayEquals(
                proposal.getIntegrityTransforms(), proposalWithoutDh.getIntegrityTransforms());
        assertTrue(proposal.getDhGroupTransforms().length == 1);
        assertTrue(proposalWithoutDh.getDhGroupTransforms().length == 0);
    }

    @Test
    public void testBuildEncryptAlgosWithNoAlgorithm() throws Exception {
        try {
            new IkeSaProposal.Builder().build();
            fail("Expected to fail when no encryption algorithm is proposed.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildEncryptAlgosWithUnrecognizedAlgorithm() throws Exception {
        try {
            new IkeSaProposal.Builder().addEncryptionAlgorithm(-1, KEY_LEN_UNUSED);
            fail("Expected to fail when unrecognized encryption algorithm is proposed.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildEncryptAlgosWithTwoModes() throws Exception {
        try {
            new IkeSaProposal.Builder()
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                    .addEncryptionAlgorithm(
                            SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12, KEY_LEN_AES_128);
            fail(
                    "Expected to fail when "
                            + "normal and combined-mode ciphers are proposed together.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildIkeProposalWithoutPrf() throws Exception {
        try {
            new IkeSaProposal.Builder()
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                    .build();
            fail("Expected to fail when PRF is not provided in IKE SA proposal.");
        } catch (IllegalArgumentException expected) {

        }
    }

    // Test throwing exception when building IKE SA Proposal with AEAD and not-none integrity
    // algorithm.
    @Test
    public void testBuildAeadWithIntegrityAlgo() throws Exception {
        try {
            new ChildSaProposal.Builder()
                    .addEncryptionAlgorithm(
                            SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12, KEY_LEN_AES_128)
                    .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_NONE)
                    .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                    .build();

            fail("Expected to fail when not-none integrity algorithm is proposed with AEAD");
        } catch (IllegalArgumentException expected) {

        }
    }

    // Test throwing exception when building IKE SA Proposal with normal mode cipher and without
    // integrity algorithm.
    @Test
    public void testBuildIkeProposalNormalCipherWithoutIntegrityAlgo() throws Exception {
        try {
            new IkeSaProposal.Builder()
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                    .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1)
                    .build();

            fail(
                    "Expected to fail when"
                            + " no integrity algorithm is proposed with non-combined cipher");
        } catch (IllegalArgumentException expected) {

        }
    }

    // Test throwing exception when building IKE SA Proposal with normal mode cipher and none-value
    // integrity algorithm.
    @Test
    public void testBuildIkeProposalNormalCipherWithNoneValueIntegrityAlgo() throws Exception {
        try {
            new IkeSaProposal.Builder()
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                    .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1)
                    .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_NONE)
                    .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                    .build();

            fail(
                    "Expected to fail when none-value integrity algorithm is proposed"
                            + " with non-combined cipher");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildIkeProposalWithoutDhGroup() throws Exception {
        try {
            new IkeSaProposal.Builder()
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                    .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                    .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                    .build();

            fail("Expected to fail when no DH Group is proposed in IKE SA proposal.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildIkeProposalWithNoneValueDhGroup() throws Exception {
        try {
            new IkeSaProposal.Builder()
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED)
                    .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                    .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                    .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                    .addDhGroup(SaProposal.DH_GROUP_NONE)
                    .build();

            fail("Expected to fail when none-value DH Group is proposed in IKE SA proposal.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testIsTransformSelectedFrom() throws Exception {
        assertTrue(SaProposal.isTransformSelectedFrom(new Transform[0], new Transform[0]));
        assertTrue(
                SaProposal.isTransformSelectedFrom(
                        new Transform[] {mEncryptionAesGcm8Transform},
                        new Transform[] {
                            mEncryptionAesGcm8Transform, mEncryptionAesGcm12Transform
                        }));
        assertTrue(
                SaProposal.isTransformSelectedFrom(
                        new Transform[] {mIntegrityNoneTransform},
                        new Transform[] {mIntegrityNoneTransform}));

        // No transform selected.
        assertFalse(
                SaProposal.isTransformSelectedFrom(
                        new Transform[0], new Transform[] {mEncryptionAesGcm8Transform}));

        // Selected transform was not part of original proposal.
        assertFalse(
                SaProposal.isTransformSelectedFrom(
                        new Transform[] {mPrfAes128XCbcTransform}, new Transform[0]));

        // More than one transform returned.
        assertFalse(
                SaProposal.isTransformSelectedFrom(
                        new Transform[] {mEncryptionAesGcm8Transform, mEncryptionAesGcm12Transform},
                        new Transform[] {
                            mEncryptionAesGcm8Transform, mEncryptionAesGcm12Transform
                        }));

        // Selected transform was not part of original proposal.
        assertFalse(
                SaProposal.isTransformSelectedFrom(
                        new Transform[] {mIntegrityNoneTransform},
                        new Transform[] {mIntegrityHmacSha1Transform}));
    }

    @Test
    public void testIsNegotiatedFromProposalWithIntegrityNone() throws Exception {
        SaProposal respProposal =
                new IkeSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                ENCRYPTION_ALGORITHM_AES_GCM_12, SaProposal.KEY_LEN_AES_128)
                        .addDhGroup(DH_GROUP_2048_BIT_MODP)
                        .addPseudorandomFunction(PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .build();

        SaProposal reqProposal =
                new IkeSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                ENCRYPTION_ALGORITHM_AES_GCM_12, SaProposal.KEY_LEN_AES_128)
                        .addEncryptionAlgorithm(
                                ENCRYPTION_ALGORITHM_AES_GCM_8, SaProposal.KEY_LEN_AES_128)
                        .addIntegrityAlgorithm(INTEGRITY_ALGORITHM_NONE)
                        .addDhGroup(DH_GROUP_1024_BIT_MODP)
                        .addDhGroup(DH_GROUP_2048_BIT_MODP)
                        .addPseudorandomFunction(PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .addPseudorandomFunction(PSEUDORANDOM_FUNCTION_SHA2_256)
                        .build();

        assertTrue(respProposal.isNegotiatedFrom(reqProposal));
    }

    @Test
    public void testGetChildSupportedEncryptionAlgorithmsBeforeSdkS() {
        assumeFalse(SdkLevel.isAtLeastS());

        assertEquals(
                SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S,
                ChildSaProposal.getSupportedEncryptionAlgorithms());
    }

    @Test
    public void testGetChildSupportedEncryptionAlgorithmsAtLeastSdkS() {
        assumeTrue(SdkLevel.isAtLeastS());

        // It is not feasible to have a hard coded expected supported algorithm set because
        // supported IPsec algorithms vary on different devices
        for (int ikeAlgoId : ChildSaProposal.getSupportedEncryptionAlgorithms()) {
            String ipSecAlgoName = IkeCipher.getIpSecAlgorithmName(ikeAlgoId);
            assertTrue(IpSecAlgorithm.getSupportedAlgorithms().contains(ipSecAlgoName));
        }

        assertTrue(
                ChildSaProposal.getSupportedEncryptionAlgorithms()
                        .containsAll(SUPPORTED_IPSEC_ENCRYPTION_BEFORE_SDK_S));
    }

    @Test
    public void testGetChildSupportedIntegrityAlgorithmsBeforeSdkS() {
        assumeFalse(SdkLevel.isAtLeastS());

        assertEquals(
                SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S,
                ChildSaProposal.getSupportedIntegrityAlgorithms());
    }

    @Test
    public void testGetChildSupportedIntegrityAlgorithmsAtLeastSdkS() {
        assumeTrue(SdkLevel.isAtLeastS());

        // It is not feasible to have a hard coded expected supported algorithm set because
        // supported IPsec algorithms vary on different devices
        for (int ikeAlgoId : ChildSaProposal.getSupportedIntegrityAlgorithms()) {
            if (ikeAlgoId != INTEGRITY_ALGORITHM_NONE) {
                String ipSecAlgoName = IkeMacIntegrity.getIpSecAlgorithmName(ikeAlgoId);
                assertTrue(IpSecAlgorithm.getSupportedAlgorithms().contains(ipSecAlgoName));
            }
        }

        assertTrue(
                ChildSaProposal.getSupportedIntegrityAlgorithms()
                        .containsAll(SUPPORTED_IPSEC_INTEGRITY_BEFORE_SDK_S));
    }

    @Test
    public void testGetIkeSupportedEncryptionAlgorithms() {
        HashSet<Integer> expectedSet = new HashSet<>();
        expectedSet = new HashSet<>();
        expectedSet.add(ENCRYPTION_ALGORITHM_3DES);
        expectedSet.add(ENCRYPTION_ALGORITHM_AES_CBC);
        expectedSet.add(ENCRYPTION_ALGORITHM_AES_CTR);
        expectedSet.add(ENCRYPTION_ALGORITHM_AES_GCM_8);
        expectedSet.add(ENCRYPTION_ALGORITHM_AES_GCM_12);
        expectedSet.add(ENCRYPTION_ALGORITHM_AES_GCM_16);
        expectedSet.add(ENCRYPTION_ALGORITHM_CHACHA20_POLY1305);

        assertEquals(expectedSet, IkeSaProposal.getSupportedEncryptionAlgorithms());
    }

    @Test
    public void testGetIkeSupportedIntegrityAlgorithms() {
        HashSet<Integer> expectedSet = new HashSet<>();
        expectedSet = new HashSet<>();
        expectedSet.add(INTEGRITY_ALGORITHM_NONE);
        expectedSet.add(INTEGRITY_ALGORITHM_HMAC_SHA1_96);
        expectedSet.add(INTEGRITY_ALGORITHM_AES_XCBC_96);
        expectedSet.add(INTEGRITY_ALGORITHM_AES_CMAC_96);
        expectedSet.add(INTEGRITY_ALGORITHM_HMAC_SHA2_256_128);
        expectedSet.add(INTEGRITY_ALGORITHM_HMAC_SHA2_384_192);
        expectedSet.add(INTEGRITY_ALGORITHM_HMAC_SHA2_512_256);

        assertEquals(expectedSet, IkeSaProposal.getSupportedIntegrityAlgorithms());
    }

    @Test
    public void testGetIkeSupportedPrfs() {
        HashSet<Integer> expectedSet = new HashSet<>();
        expectedSet = new HashSet<>();
        expectedSet.add(PSEUDORANDOM_FUNCTION_HMAC_SHA1);
        expectedSet.add(PSEUDORANDOM_FUNCTION_AES128_XCBC);
        expectedSet.add(PSEUDORANDOM_FUNCTION_SHA2_256);
        expectedSet.add(PSEUDORANDOM_FUNCTION_SHA2_384);
        expectedSet.add(PSEUDORANDOM_FUNCTION_SHA2_512);
        expectedSet.add(PSEUDORANDOM_FUNCTION_AES128_CMAC);

        assertEquals(expectedSet, IkeSaProposal.getSupportedPseudorandomFunctions());
    }

    @Test
    public void testGetSupportedDhGroups() {
        HashSet<Integer> expectedSet = new HashSet<>();
        expectedSet = new HashSet<>();
        expectedSet.add(DH_GROUP_NONE);
        expectedSet.add(DH_GROUP_1024_BIT_MODP);
        expectedSet.add(DH_GROUP_1536_BIT_MODP);
        expectedSet.add(DH_GROUP_2048_BIT_MODP);
        expectedSet.add(DH_GROUP_3072_BIT_MODP);
        expectedSet.add(DH_GROUP_4096_BIT_MODP);
        expectedSet.add(DH_GROUP_CURVE_25519);

        assertEquals(expectedSet, IkeSaProposal.getSupportedDhGroups());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildChildProposalWithUnsupportedEncryptionAlgo() throws Exception {
        new ChildSaProposal.Builder()
                .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES, KEY_LEN_UNUSED);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildChildProposalWithUnsupportedIntegrityAlgo() throws Exception {
        new ChildSaProposal.Builder().addIntegrityAlgorithm(ALGORITHM_ID_INVALID);
    }
}
