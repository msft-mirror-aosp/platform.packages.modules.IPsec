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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.android.ike.ikev2.exceptions.InvalidSyntaxException;

import org.junit.Test;

public final class IkeKePayloadTest {
    private static final String KE_PAYLOAD_RAW_PACKET =
            "00020000b4a2faf4bb54878ae21d638512ece55d9236fc50"
                    + "46ab6cef82220f421f3ce6361faf36564ecb6d28798a94aa"
                    + "d7b2b4b603ddeaaa5630adb9ece8ac37534036040610ebdd"
                    + "92f46bef84f0be7db860351843858f8acf87056e272377f7"
                    + "0c9f2d81e29c7b0ce4f291a3a72476bb0b278fd4b7b0a4c2"
                    + "6bbeb08214c7071376079587";

    private static final boolean CRITICAL_BIT = false;
    @IkeKePayload.DhGroup
    private static final int EXPECTED_DH_GROUP = IkeKePayload.DH_GROUP_1024_BIT_MODP;

    private static final String KEY_EXCHANGE_DATA_RAW_PACKET =
            "b4a2faf4bb54878ae21d638512ece55d9236fc5046ab6cef"
                    + "82220f421f3ce6361faf36564ecb6d28798a94aad7b2b4b6"
                    + "03ddeaaa5630adb9ece8ac37534036040610ebdd92f46bef"
                    + "84f0be7db860351843858f8acf87056e272377f70c9f2d81"
                    + "e29c7b0ce4f291a3a72476bb0b278fd4b7b0a4c26bbeb082"
                    + "14c7071376079587";

    @Test
    public void testDecodeIkeKePayload() throws Exception {
        byte[] inputPacket = MessageTestUtil.hexStringToByteArray(KE_PAYLOAD_RAW_PACKET);

        IkeKePayload payload = new IkeKePayload(CRITICAL_BIT, inputPacket);

        assertEquals(EXPECTED_DH_GROUP, payload.dhGroup);

        byte[] keyExchangeData = MessageTestUtil.hexStringToByteArray(KEY_EXCHANGE_DATA_RAW_PACKET);
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
        byte[] inputPacket = MessageTestUtil.hexStringToByteArray(badKeyPayloadPacket);

        try {
            IkeKePayload payload = new IkeKePayload(CRITICAL_BIT, inputPacket);
            fail("Expected InvalidSyntaxException: KE data length doesn't match its DH group type");
        } catch (InvalidSyntaxException expected) {
        }
    }
}
