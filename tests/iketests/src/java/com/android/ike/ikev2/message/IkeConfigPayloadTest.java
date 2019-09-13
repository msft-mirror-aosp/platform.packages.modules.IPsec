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
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttribute;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Address;

import libcore.net.InetAddressUtils;

import org.junit.Test;

import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.util.LinkedList;
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
    private static final byte[] IPV4_ADDRESS_ATTRIBUTE_WITH_VALUE =
            TestUtils.hexStringToByteArray("000100040a0a0a01");
    private static final byte[] IPV4_ADDRESS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00010000");

    private static final byte[] IPV6_ADDRESS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00080000");
    private static final byte[] IPV4_DNS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00030000");
    private static final byte[] IPV6_DNS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("000a0000");

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
    }

    private ConfigAttribute makeMockAttribute(byte[] encodedAttribute) {
        ConfigAttribute mockAttribute = mock(ConfigAttribute.class);

        when(mockAttribute.getAttributeLen()).thenReturn(encodedAttribute.length);

        doAnswer(
                (invocation) -> {
                    ByteBuffer buffer = (ByteBuffer) invocation.getArguments()[0];
                    buffer.put(encodedAttribute);
                    return null;
                })
                .when(mockAttribute)
                .encodeAttributeToByteBuffer(any(ByteBuffer.class));

        return mockAttribute;
    }

    @Test
    public void testBuildAndEncodeOutboundConfig() throws Exception {
        List<ConfigAttribute> mockAttributeList = new LinkedList<>();
        mockAttributeList.add(makeMockAttribute(IPV4_ADDRESS_ATTRIBUTE_WITHOUT_VALUE));
        mockAttributeList.add(makeMockAttribute(IPV6_ADDRESS_ATTRIBUTE_WITHOUT_VALUE));
        mockAttributeList.add(makeMockAttribute(IPV4_DNS_ATTRIBUTE_WITHOUT_VALUE));
        mockAttributeList.add(makeMockAttribute(IPV6_DNS_ATTRIBUTE_WITHOUT_VALUE));
        IkeConfigPayload configPayload = new IkeConfigPayload(false /*isReply*/, mockAttributeList);

        assertEquals(PAYLOAD_TYPE_CP, configPayload.payloadType);
        assertFalse(configPayload.isCritical);
        assertEquals(CONFIG_TYPE_REQUEST, configPayload.configType);
        assertEquals(mockAttributeList, configPayload.recognizedAttributeList);

        ByteBuffer buffer = ByteBuffer.allocate(configPayload.getPayloadLength());
        configPayload.encodeToByteBuffer(PAYLOAD_TYPE_NOTIFY, buffer);
        assertArrayEquals(CONFIG_REQ_PAYLOAD, buffer.array());
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

    @Test
    public void testEncodeIpv4AddressWithValue() throws Exception {
        ConfigAttributeIpv4Address attributeIp4Address =
                new ConfigAttributeIpv4Address(IPV4_ADDRESS);

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, attributeIp4Address.attributeType);
        assertEquals(IPV4_ADDRESS, attributeIp4Address.address);

        ByteBuffer buffer = ByteBuffer.allocate(attributeIp4Address.getAttributeLen());
        attributeIp4Address.encodeAttributeToByteBuffer(buffer);
        assertArrayEquals(IPV4_ADDRESS_ATTRIBUTE_WITH_VALUE, buffer.array());
    }

    @Test
    public void testEncodeIpv4AddressWithoutValue() throws Exception {
        ConfigAttributeIpv4Address attributeIp4Address = new ConfigAttributeIpv4Address();

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, attributeIp4Address.attributeType);
        assertNull(attributeIp4Address.address);

        ByteBuffer buffer = ByteBuffer.allocate(attributeIp4Address.getAttributeLen());
        attributeIp4Address.encodeAttributeToByteBuffer(buffer);
        assertArrayEquals(IPV4_ADDRESS_ATTRIBUTE_WITHOUT_VALUE, buffer.array());
    }
}
