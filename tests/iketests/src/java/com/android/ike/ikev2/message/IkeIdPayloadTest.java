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

import org.junit.Test;

public final class IkeIdPayloadTest {
    private static final String ID_PAYLOAD_INITIATOR_FQDN_HEX_STRING = "020000006576697461";

    @Test
    public void testDecodeIdPayload() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(ID_PAYLOAD_INITIATOR_FQDN_HEX_STRING);
        IkeIdPayload payload = new IkeIdPayload(false, inputPacket, true);
        assertEquals(IkePayload.PAYLOAD_TYPE_ID_INITIATOR, payload.payloadType);
    }
}
