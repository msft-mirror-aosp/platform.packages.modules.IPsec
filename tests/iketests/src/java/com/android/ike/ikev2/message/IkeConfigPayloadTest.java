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

package com.android.ike.ikev2.message;

import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_ADDRESS;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_TYPE_REPLY;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_TYPE_REQUEST;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_CP;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttribute;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Address;

import libcore.net.InetAddressUtils;

import org.junit.Test;

import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.util.List;

public final class IkeConfigPayloadTest {
    private static final String CONFIG_REQ_PAYLOAD_HEX =
            "2900001801000000000100000008000000030000000a0000";
    private static final String CONFIG_RESP_PAYLOAD_HEX =
            "2100002002000000000100040a0a0a0100030004080808080003000408080404";

    private static final byte[] CONFIG_REQ_PAYLOAD =
            TestUtils.hexStringToByteArray(CONFIG_REQ_PAYLOAD_HEX);
    private static final byte[] CONFIG_RESP_PAYLOAD =
            TestUtils.hexStringToByteArray(CONFIG_RESP_PAYLOAD_HEX);

    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("10.10.10.1"));

    private IkeConfigPayload verifyDecodeHeaderAndGetPayload(
            IkePayload payload, int expectedConfigType) {
        assertEquals(PAYLOAD_TYPE_CP, payload.payloadType);
        assertFalse(payload.isCritical);
        assertTrue(payload instanceof IkeConfigPayload);

        IkeConfigPayload configPayload = (IkeConfigPayload) payload;
        assertEquals(expectedConfigType, configPayload.configType);

        return configPayload;
    }

    @Test
    public void testDecodeConfigRequest() throws Exception {
        IkePayload payload =
                IkePayloadFactory.getIkePayload(
                                PAYLOAD_TYPE_CP,
                                false /*isResp*/,
                                ByteBuffer.wrap(CONFIG_REQ_PAYLOAD))
                        .first;

        IkeConfigPayload configPayload =
                verifyDecodeHeaderAndGetPayload(payload, CONFIG_TYPE_REQUEST);

        List<ConfigAttribute> recognizedAttributeList = configPayload.recognizedAttributeList;
        assertEquals(1, recognizedAttributeList.size());

        ConfigAttributeIpv4Address attributeIp4Address =
                (ConfigAttributeIpv4Address) recognizedAttributeList.get(0);
        assertEquals(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, attributeIp4Address.attributeType);
        assertNull(attributeIp4Address.address);

        // TODO: Verify decoded other types of attributes when they are supported.
    }

    @Test
    public void testDecodeConfigResponse() throws Exception {
        IkePayload payload =
                IkePayloadFactory.getIkePayload(
                                PAYLOAD_TYPE_CP,
                                true /*isResp*/,
                                ByteBuffer.wrap(CONFIG_RESP_PAYLOAD))
                        .first;

        IkeConfigPayload configPayload =
                verifyDecodeHeaderAndGetPayload(payload, CONFIG_TYPE_REPLY);

        List<ConfigAttribute> recognizedAttributeList = configPayload.recognizedAttributeList;
        assertEquals(1, recognizedAttributeList.size());

        ConfigAttributeIpv4Address attributeIp4Address =
                (ConfigAttributeIpv4Address) recognizedAttributeList.get(0);
        assertEquals(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, attributeIp4Address.attributeType);
        assertEquals(IPV4_ADDRESS, attributeIp4Address.address);

        // TODO: Verify decoded other types of attributes when they are supported.
    }

    @Test
    public void testBuildOutboundConfig() throws Exception {
        List<ConfigAttribute> mockAttributeList = mock(List.class);
        IkeConfigPayload configPayload = new IkeConfigPayload(false /*isReply*/, mockAttributeList);

        assertEquals(PAYLOAD_TYPE_CP, configPayload.payloadType);
        assertFalse(configPayload.isCritical);
        assertEquals(CONFIG_TYPE_REQUEST, configPayload.configType);
        assertEquals(mockAttributeList, configPayload.recognizedAttributeList);
    }

    @Test
    public void testDecodeIpv4AddressWithValue() throws Exception {
        ConfigAttributeIpv4Address attributeIp4Address =
                new ConfigAttributeIpv4Address(IPV4_ADDRESS.getAddress());

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, attributeIp4Address.attributeType);
        assertEquals(IPV4_ADDRESS, attributeIp4Address.address);
    }

    @Test
    public void testDecodeIpv4AddressWithoutValue() throws Exception {
        ConfigAttributeIpv4Address attributeIp4Address =
                new ConfigAttributeIpv4Address(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, attributeIp4Address.attributeType);
        assertNull(attributeIp4Address.address);
    }

    @Test
    public void testDecodeIpv4AddressWithInvalidValue() throws Exception {
        byte[] invalidValue = new byte[] {1};

        try {
            ConfigAttributeIpv4Address attributeIp4Address =
                    new ConfigAttributeIpv4Address(invalidValue);
            fail("Expected to fail due to invalid attribute value");
        } catch (InvalidSyntaxException expected) {
        }
    }

    // TODO: Testing encoding attributes
}
