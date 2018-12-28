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

package com.android.ike.ikev2.message;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import javax.crypto.Mac;

public final class IkeAuthPayloadTest {
    private static final String PSK_AUTH_PAYLOAD_HEX_STRING =
            "02000000df7c038aefaaa32d3f44b228b52a332744dfb2c1";
    private static final String PSK_AUTH_PAYLOAD_SIGNATRUE_HEX_STRING =
            "df7c038aefaaa32d3f44b228b52a332744dfb2c1";
    private static final String PSK_ID_PAYLOAD_HEX_STRING = "010000000a50500d";
    private static final String PSK_SKP_HEX_STRING = "094787780EE466E2CB049FA327B43908BC57E485";
    private static final String PSK_SIGNED_OCTETS_APPENDIX_HEX_STRING =
            "D83B20CC6A0932B2A7CEF26E4020ABAAB64F0C6A";

    private static final int AUTH_METHOD_POSITION = 0;

    private static final String PRF_HMAC_SHA1_ALGO_NAME = "HmacSHA1";

    @Test
    public void testDecodeIkeAuthPayload() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(PSK_AUTH_PAYLOAD_HEX_STRING);
        IkeAuthPayload payload = IkeAuthPayload.getIkeAuthPayload(false, inputPacket);

        assertEquals(IkeAuthPayload.AUTH_METHOD_PRE_SHARED_KEY, payload.authMethod);
        assertTrue(payload instanceof IkeAuthPskPayload);

        byte[] expectedSignature =
                TestUtils.hexStringToByteArray(PSK_AUTH_PAYLOAD_SIGNATRUE_HEX_STRING);
        assertArrayEquals(expectedSignature, ((IkeAuthPskPayload) payload).signature);
    }

    @Test
    public void testDecodeIkeAuthPayloadWithUnsupportedMethod() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(PSK_AUTH_PAYLOAD_HEX_STRING);
        inputPacket[AUTH_METHOD_POSITION] = 0;
        try {
            IkeAuthPayload payload = IkeAuthPayload.getIkeAuthPayload(false, inputPacket);
            fail("Expected Exception: authentication method is not supported");
        } catch (UnsupportedOperationException e) {
            // TODO: Catch AuthenticationFailedException after it is implemented.
        }
    }

    @Test
    public void testSignWithPrf() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(PSK_AUTH_PAYLOAD_HEX_STRING);

        IkeAuthPayload payload = IkeAuthPayload.getIkeAuthPayload(false, inputPacket);

        Mac prfMac = Mac.getInstance(PRF_HMAC_SHA1_ALGO_NAME, IkeMessage.getSecurityProvider());
        byte[] skpBytes = TestUtils.hexStringToByteArray(PSK_SKP_HEX_STRING);
        byte[] idBytes = TestUtils.hexStringToByteArray(PSK_ID_PAYLOAD_HEX_STRING);
        byte[] calculatedBytes = payload.signWithPrf(prfMac, skpBytes, idBytes);

        byte[] expectedBytes =
                TestUtils.hexStringToByteArray(PSK_SIGNED_OCTETS_APPENDIX_HEX_STRING);
        assertArrayEquals(expectedBytes, calculatedBytes);
    }
}
