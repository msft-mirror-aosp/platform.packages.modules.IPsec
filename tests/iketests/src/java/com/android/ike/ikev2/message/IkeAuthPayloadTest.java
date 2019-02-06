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

public final class IkeAuthPayloadTest {
    private static final String AUTH_PAYLOAD_PSK_HEX_STRING =
            "02000000a04554c4d5b98572556b5542d767666c";
    private static final String AUTH_PAYLOAD_PSK_SIGNATRUE_HEX_STRING =
            "a04554c4d5b98572556b5542d767666c";

    private static final int AUTH_METHOD_POSITION = 0;

    @Test
    public void testDecodeIkeAuthPayload() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(AUTH_PAYLOAD_PSK_HEX_STRING);
        IkeAuthPayload payload = IkeAuthPayload.getIkeAuthPayload(false, inputPacket);

        assertEquals(IkeAuthPayload.AUTH_METHOD_PRE_SHARED_KEY, payload.authMethod);
        assertTrue(payload instanceof IkeAuthPskPayload);

        byte[] expectedSignature =
                TestUtils.hexStringToByteArray(AUTH_PAYLOAD_PSK_SIGNATRUE_HEX_STRING);
        assertArrayEquals(expectedSignature, ((IkeAuthPskPayload) payload).signature);
    }

    @Test
    public void testDecodeIkeAuthPayloadWithUnsupportedMethod() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(AUTH_PAYLOAD_PSK_HEX_STRING);
        inputPacket[AUTH_METHOD_POSITION] = 0;
        try {
            IkeAuthPayload payload = IkeAuthPayload.getIkeAuthPayload(false, inputPacket);
            fail("Expected Exception: authentication method is not supported");
        } catch (UnsupportedOperationException e) {
            // TODO: Catch AuthenticationFailedException after it is implemented.
        }
    }
}
