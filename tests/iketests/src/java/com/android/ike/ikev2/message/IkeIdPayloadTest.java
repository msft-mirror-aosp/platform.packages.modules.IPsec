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

import com.android.ike.ikev2.IkeIdentification;
import com.android.ike.ikev2.IkeIdentification.IkeIpv4AddrIdentification;
import com.android.ike.ikev2.exceptions.AuthenticationFailedException;

import org.junit.Test;

import java.net.Inet4Address;

public final class IkeIdPayloadTest {
    private static final String ID_PAYLOAD_RESPONDER_IP4_ADDR_HEX_STRING = "010000000a505050";
    private static final String ID_PAYLOAD_INITIATOR_FQDN_HEX_STRING = "020000006576697461";
    private static final String IP4_ADDR_STRING = "10.80.80.80";

    @Test
    public void testDecodeIp4AddrIdPayload() throws Exception {
        byte[] inputPacket =
                TestUtils.hexStringToByteArray(ID_PAYLOAD_RESPONDER_IP4_ADDR_HEX_STRING);
        IkeIdPayload payload = new IkeIdPayload(false, inputPacket, false);

        assertEquals(IkePayload.PAYLOAD_TYPE_ID_RESPONDER, payload.payloadType);
        assertEquals(IkeIdentification.ID_TYPE_IPV4_ADDR, payload.ikeId.idType);
        IkeIpv4AddrIdentification ikeId = (IkeIpv4AddrIdentification) payload.ikeId;
        Inet4Address expectedAddr = (Inet4Address) Inet4Address.getByName(IP4_ADDR_STRING);
        assertEquals(expectedAddr, ikeId.ipv4Address);
    }

    @Test
    public void testDecodeUnsupportedIdType() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(ID_PAYLOAD_INITIATOR_FQDN_HEX_STRING);

        try {
            new IkeIdPayload(false, inputPacket, true);
            fail("Expected AuthenticationFailedException: ID Type is unsupported.");
        } catch (AuthenticationFailedException expected) {
        }
    }
}
