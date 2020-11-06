/*
 * Copyright (C) 2018 The Android Open Source Project
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

package com.android.internal.net.ipsec.ike.message;

import static com.android.internal.net.TestUtils.createMockRandomFactory;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.net.ipsec.ike.SaProposal;
import android.net.ipsec.ike.exceptions.protocol.InvalidSyntaxException;

import com.android.internal.net.TestUtils;
import com.android.internal.net.ipsec.ike.IkeDhParams;
import com.android.internal.net.utils.BigIntegerUtils;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.spec.DHPrivateKeySpec;

public final class IkeKePayloadTest {
    private static final String KE_PAYLOAD_GENERIC_HEADER = "28000088";
    private static final String KE_PAYLOAD_RAW_PACKET =
            "00020000b4a2faf4bb54878ae21d638512ece55d9236fc50"
                    + "46ab6cef82220f421f3ce6361faf36564ecb6d28798a94aa"
                    + "d7b2b4b603ddeaaa5630adb9ece8ac37534036040610ebdd"
                    + "92f46bef84f0be7db860351843858f8acf87056e272377f7"
                    + "0c9f2d81e29c7b0ce4f291a3a72476bb0b278fd4b7b0a4c2"
                    + "6bbeb08214c7071376079587";

    private static final boolean CRITICAL_BIT = false;

    @IkePayload.PayloadType
    private static final int NEXT_PAYLOAD_TYPE = IkePayload.PAYLOAD_TYPE_NONCE;

    private static final int EXPECTED_DH_GROUP = SaProposal.DH_GROUP_1024_BIT_MODP;

    private static final int EXPECTED_KE_DATA_LEN = 128;

    private static final String KEY_EXCHANGE_DATA_RAW_PACKET =
            "b4a2faf4bb54878ae21d638512ece55d9236fc5046ab6cef"
                    + "82220f421f3ce6361faf36564ecb6d28798a94aad7b2b4b6"
                    + "03ddeaaa5630adb9ece8ac37534036040610ebdd92f46bef"
                    + "84f0be7db860351843858f8acf87056e272377f70c9f2d81"
                    + "e29c7b0ce4f291a3a72476bb0b278fd4b7b0a4c26bbeb082"
                    + "14c7071376079587";

    private static final String PRIME_1024_BIT_MODP_160_SUBGROUP =
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
                    + "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
                    + "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
                    + "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
                    + "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
                    + "DF1FB2BC2E4A4371";
    private static final String GENERATOR_1024_BIT_MODP_160_SUBGROUP =
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
                    + "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
                    + "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
                    + "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
                    + "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
                    + "855E6EEB22B3B2E5";
    private static final String PRIVATE_KEY_LOCAL = "B9A3B3AE8FEFC1A2930496507086F8455D48943E";
    private static final String PUBLIC_KEY_REMOTE =
            "717A6CB053371FF4A3B932941C1E5663F861A1D6AD34AE66"
                    + "576DFB98F6C6CBF9DDD5A56C7833F6BCFDFF095582AD868E"
                    + "440E8D09FD769E3CECCDC3D3B1E4CFA057776CAAF9739B6A"
                    + "9FEE8E7411F8D6DAC09D6A4EDB46CC2B5D5203090EAE6126"
                    + "311E53FD2C14B574E6A3109A3DA1BE41BDCEAA186F5CE067"
                    + "16A2B6A07B3C33FE";
    private static final String EXPECTED_SHARED_KEY =
            "5C804F454D30D9C4DF85271F93528C91DF6B48AB5F80B3B5"
                    + "9CAAC1B28F8ACBA9CD3E39F3CB614525D9521D2E644C53B8"
                    + "07B810F340062F257D7D6FBFE8D5E8F072E9B6E9AFDA9413"
                    + "EAFB2E8B0699B1FB5A0CACEDDEAEAD7E9CFBB36AE2B42083"
                    + "5BD83A19FB0B5E96BF8FA4D09E345525167ECD9155416F46"
                    + "F408ED31B63C6E6D";
    private static final String KEY_EXCHANGE_ALGORITHM = "DH";

    private DHPrivateKeySpec mPrivateKeySpec;

    @Before
    public void setUp() throws Exception {
        BigInteger primeValue =
                BigIntegerUtils.unsignedHexStringToBigInteger(PRIME_1024_BIT_MODP_160_SUBGROUP);
        BigInteger baseGenValue =
                BigIntegerUtils.unsignedHexStringToBigInteger(GENERATOR_1024_BIT_MODP_160_SUBGROUP);
        BigInteger privateKeyValue =
                BigIntegerUtils.unsignedHexStringToBigInteger(PRIVATE_KEY_LOCAL);
        mPrivateKeySpec = new DHPrivateKeySpec(privateKeyValue, primeValue, baseGenValue);
    }

    @Test
    public void testDecodeIkeKePayload() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(KE_PAYLOAD_RAW_PACKET);

        IkeKePayload payload = new IkeKePayload(CRITICAL_BIT, inputPacket);

        assertFalse(payload.isOutbound);
        assertEquals(EXPECTED_DH_GROUP, payload.dhGroup);

        byte[] keyExchangeData = TestUtils.hexStringToByteArray(KEY_EXCHANGE_DATA_RAW_PACKET);
        assertEquals(keyExchangeData.length, payload.keyExchangeData.length);
        for (int i = 0; i < keyExchangeData.length; i++) {
            assertEquals(keyExchangeData[i], payload.keyExchangeData[i]);
        }
    }

    @Test
    public void testDecodeIkeKePayloadWithInvalidKeData() throws Exception {
        // Cut bytes of KE data from original KE payload
        String badKeyPayloadPacket =
                KE_PAYLOAD_RAW_PACKET.substring(0, KE_PAYLOAD_RAW_PACKET.length() - 2);
        byte[] inputPacket = TestUtils.hexStringToByteArray(badKeyPayloadPacket);

        try {
            IkeKePayload payload = new IkeKePayload(CRITICAL_BIT, inputPacket);
            fail("Expected InvalidSyntaxException: KE data length doesn't match its DH group type");
        } catch (InvalidSyntaxException expected) {
        }
    }

    @Test
    public void testEncodeIkeKePayload() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(KE_PAYLOAD_RAW_PACKET);
        IkeKePayload payload = new IkeKePayload(CRITICAL_BIT, inputPacket);

        ByteBuffer byteBuffer = ByteBuffer.allocate(payload.getPayloadLength());
        payload.encodeToByteBuffer(NEXT_PAYLOAD_TYPE, byteBuffer);

        byte[] expectedKePayload =
                TestUtils.hexStringToByteArray(KE_PAYLOAD_GENERIC_HEADER + KE_PAYLOAD_RAW_PACKET);
        assertArrayEquals(expectedKePayload, byteBuffer.array());
    }

    @Test
    public void testGetIkeKePayload() throws Exception {
        IkeKePayload payload =
                new IkeKePayload(SaProposal.DH_GROUP_1024_BIT_MODP, createMockRandomFactory());

        // Test DHPrivateKeySpec
        assertTrue(payload.isOutbound);
        DHPrivateKeySpec privateKeySpec = payload.localPrivateKey;

        BigInteger primeValue = privateKeySpec.getP();
        BigInteger expectedPrimeValue = new BigInteger(IkeDhParams.PRIME_1024_BIT_MODP, 16);
        assertEquals(0, expectedPrimeValue.compareTo(primeValue));

        BigInteger genValue = privateKeySpec.getG();
        BigInteger expectedGenValue = BigInteger.valueOf(IkeDhParams.BASE_GENERATOR_MODP);
        assertEquals(0, expectedGenValue.compareTo(genValue));

        // Test IkeKePayload
        assertEquals(EXPECTED_DH_GROUP, payload.dhGroup);
        assertEquals(EXPECTED_KE_DATA_LEN, payload.keyExchangeData.length);
    }

    // Since we didn't find test data for DH group types supported in current IKE library, we use
    // test data for "1024-bit MODP Group with 160-bit Prime Order Subgroup" from RFC 5114. The main
    // difference is that it uses weaker Prime and Generator values and requires more complicated
    // recipient test in real Key Exchange process. But it is suitable for testing.
    @Test
    public void testGetSharedkey() throws Exception {
        byte[] remotePublicKey = TestUtils.hexStringToByteArray(PUBLIC_KEY_REMOTE);
        byte[] sharedKeyBytes = IkeKePayload.getSharedKey(mPrivateKeySpec, remotePublicKey);

        byte[] expectedSharedKeyBytes = TestUtils.hexStringToByteArray(EXPECTED_SHARED_KEY);
        assertTrue(Arrays.equals(expectedSharedKeyBytes, sharedKeyBytes));
    }

    @Test
    public void testGetSharedkey1536Modp() throws Exception {
        final String publicKeyRemoteHex =
                "1907B9796CD091E3FCBEDDFE8113E1D9463F65DCFD5371FB"
                        + "A4E50DF78B059E3C84C8F6D53E597DF7190016B0D44A8F78"
                        + "52DAE8602B74423848012FF254F552D521579088D8AB8BAF"
                        + "2523CDC55BCC6BD2C59153A678498FB1F2EC2953F49C2109"
                        + "1F38B729ADF50BB02B0FE82908FFC867004B63A5CC6AD183"
                        + "49F57B346F870B928D018BDC97CE44DA187CE975919E97DA"
                        + "3A9D1827D5C9C8881A6355478F7602099AF56C802DE9AD54"
                        + "1295B3B238BAF28628ADDFAB9C9A6886EE24F6671B9151D5";
        final String privateKeyXValueHex =
                "a62c4aca7ec6787c075fe1690edbd768b406fe5b6bbd6d77"
                        + "1913143c75289f0e10eded5428615fa0b61271bd739e15b8"
                        + "99243de341511fbf0ab87d309746d690f1b98ada5d76b6fc"
                        + "33e6b21f59d7d5f4d2cd4e7cb1b8da2cdbc3914ff6e1a1e2"
                        + "65512ef09455dd271419fc7b7584ca5e61212c68b128307c"
                        + "bf31a4d8ce51bd20112dbb846edb5fc8d7d4c2b94ac84ba3"
                        + "e4c7805f3565ba9e1bb2724f8f5aebf9c14fca8ed6638566"
                        + "03b02bc569b868100a5e4c3906f3a9344eb57d2daeba0562";
        final String expectedSharedKeyHex =
                "0BDBC66787BCBE1F899C070CCC05E9C728ED764E93DFE454"
                        + "FD6B1AE691382FCB5B36656F5D10B85E914230071F098004"
                        + "67B594A2C9902790EDAA792CE389376BB491283482AEBC75"
                        + "225474DCD4269F92246467164A9CEFFA14371AC3477F17DB"
                        + "60EE21D85B76BF6B46B851C685E385CDFD213B5450043F56"
                        + "CE0C98CFF91D63C00FED85FE9DD318673E4E7F16BC052016"
                        + "A5D347E045EFABD7ABA6D35E53E64972779E11AFD3561076"
                        + "65F0AC3A5E64C6C065786F5B63A9B7BC993C85234D457ABB";

        BigInteger primeValue =
                BigIntegerUtils.unsignedHexStringToBigInteger(IkeDhParams.PRIME_1536_BIT_MODP);
        BigInteger baseGenValue = BigInteger.valueOf(IkeDhParams.BASE_GENERATOR_MODP);
        BigInteger privateKeyValue =
                BigIntegerUtils.unsignedHexStringToBigInteger(privateKeyXValueHex);
        DHPrivateKeySpec privateKeySpec =
                new DHPrivateKeySpec(privateKeyValue, primeValue, baseGenValue);

        byte[] remotePublicKey = TestUtils.hexStringToByteArray(publicKeyRemoteHex);
        byte[] sharedKeyBytes = IkeKePayload.getSharedKey(privateKeySpec, remotePublicKey);

        byte[] expectedSharedKeyBytes = TestUtils.hexStringToByteArray(expectedSharedKeyHex);
        assertTrue(Arrays.equals(expectedSharedKeyBytes, sharedKeyBytes));
    }

    @Test
    public void testGetSharedkeyWithInvalidRemoteKey() throws Exception {
        byte[] remotePublicKey = TestUtils.hexStringToByteArray(PRIME_1024_BIT_MODP_160_SUBGROUP);

        try {
            byte[] sharedKeyBytes = IkeKePayload.getSharedKey(mPrivateKeySpec, remotePublicKey);
            fail("Expected to fail because of invalid remote public key.");
        } catch (GeneralSecurityException expected) {
        }
    }
}
