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
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_DNS;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_NETMASK;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_SUBNET;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_ADDRESS;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_DNS;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_SUBNET;
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

import android.net.LinkAddress;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttrIpv4AddressBase;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttrIpv6AddrRangeBase;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttribute;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Address;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Dns;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Netmask;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Subnet;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv6Address;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv6Dns;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv6Subnet;

import libcore.net.InetAddressUtils;

import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

public final class IkeConfigPayloadTest {
    private static final String CONFIG_REQ_PAYLOAD_HEX =
            "2900001801000000000100000008000000030000000a0000";
    private static final String CONFIG_RESP_PAYLOAD_HEX =
            "210000200200000000010004c000026400030004080808080003000408080404";

    private static final byte[] CONFIG_REQ_PAYLOAD =
            TestUtils.hexStringToByteArray(CONFIG_REQ_PAYLOAD_HEX);
    private static final byte[] CONFIG_RESP_PAYLOAD =
            TestUtils.hexStringToByteArray(CONFIG_RESP_PAYLOAD_HEX);

    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.100"));
    private static final Inet4Address IPV4_NETMASK =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("255.255.255.240"));
    private static final int IP4_PREFIX_LEN = 28;
    private static final LinkAddress IPV4_LINK_ADDRESS =
            new LinkAddress(IPV4_ADDRESS, IP4_PREFIX_LEN);

    private static final byte[] IPV4_ADDRESS_ATTRIBUTE_WITH_VALUE =
            TestUtils.hexStringToByteArray("00010004c0000264");
    private static final byte[] IPV4_ADDRESS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00010000");

    private static final byte[] IPV4_NETMASK_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00020000");

    private static final Inet4Address IPV4_DNS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("8.8.8.8"));
    private static final byte[] IPV4_DNS_ATTRIBUTE_VALUE =
            TestUtils.hexStringToByteArray("08080808");
    private static final byte[] IPV4_DNS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00030000");

    private static final byte[] IPV4_SUBNET_ATTRIBUTE_VALUE =
            TestUtils.hexStringToByteArray("c0000264fffffff0");
    private static final byte[] IPV4_SUBNET_ATTRIBUTE_WITH_VALUE =
            TestUtils.hexStringToByteArray("000d0008c0000264fffffff0");
    private static final byte[] IPV4_SUBNET_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("000d0000");

    private static final Inet6Address IPV6_ADDRESS =
            (Inet6Address) (InetAddressUtils.parseNumericAddress("2001:db8::1"));
    private static final int IP6_PREFIX_LEN = 64;
    private static final LinkAddress IPV6_LINK_ADDRESS =
            new LinkAddress(IPV6_ADDRESS, IP6_PREFIX_LEN);

    private static final byte[] IPV6_ADDRESS_ATTRIBUTE_VALUE =
            TestUtils.hexStringToByteArray("20010db800000000000000000000000140");
    private static final byte[] IPV6_ADDRESS_ATTRIBUTE_WITH_VALUE =
            TestUtils.hexStringToByteArray("0008001120010db800000000000000000000000140");
    private static final byte[] IPV6_ADDRESS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("00080000");

    private static final byte[] IPV6_SUBNET_ATTRIBUTE_VALUE = IPV6_ADDRESS_ATTRIBUTE_VALUE;
    private static final byte[] IPV6_SUBNET_ATTRIBUTE_WITH_VALUE =
            TestUtils.hexStringToByteArray("000f001120010db800000000000000000000000140");
    private static final byte[] IPV6_SUBNET_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("000f0000");

    private static final Inet6Address IPV6_DNS =
            (Inet6Address) (InetAddressUtils.parseNumericAddress("2001:db8:100::1"));
    private static final byte[] IPV6_DNS_ATTRIBUTE_WITHOUT_VALUE =
            TestUtils.hexStringToByteArray("000a0000");

    private Inet4Address[] mNetMasks;
    private int[] mIpv4PrefixLens;

    @Before
    public void setUp() throws Exception {
        mNetMasks =
                new Inet4Address[] {
                    (Inet4Address) (InetAddressUtils.parseNumericAddress("0.0.0.0")),
                    (Inet4Address) (InetAddressUtils.parseNumericAddress("255.255.255.255")),
                    (Inet4Address) (InetAddressUtils.parseNumericAddress("255.255.255.240"))
                };
        mIpv4PrefixLens = new int[] {0, 32, 28};
    }

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

    private void verifyBuildAndEncodeAttributeCommon(
            ConfigAttribute attribute, int expectedAttributeType, byte[] expectedEncodedAttribute) {
        assertEquals(expectedAttributeType, attribute.attributeType);

        ByteBuffer buffer = ByteBuffer.allocate(attribute.getAttributeLen());
        attribute.encodeAttributeToByteBuffer(buffer);
        assertArrayEquals(expectedEncodedAttribute, buffer.array());
    }

    private void verifyEncodeIpv4AddresBaseAttribute(
            ConfigAttrIpv4AddressBase attribute,
            int expectedAttributeType,
            byte[] expectedEncodedAttribute,
            Inet4Address expectedAddress) {
        verifyBuildAndEncodeAttributeCommon(
                attribute, expectedAttributeType, expectedEncodedAttribute);
        assertEquals(expectedAddress, attribute.address);
    }

    private void verifyEncodeIpv6RangeBaseAttribute(
            ConfigAttrIpv6AddrRangeBase attribute,
            int expectedAttributeType,
            byte[] expectedEncodedAttribute,
            LinkAddress expectedLinkAddress) {
        verifyBuildAndEncodeAttributeCommon(
                attribute, expectedAttributeType, expectedEncodedAttribute);
        assertEquals(expectedLinkAddress, attribute.linkAddress);
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

        verifyEncodeIpv4AddresBaseAttribute(
                attributeIp4Address,
                CONFIG_ATTR_INTERNAL_IP4_ADDRESS,
                IPV4_ADDRESS_ATTRIBUTE_WITH_VALUE,
                IPV4_ADDRESS);
    }

    @Test
    public void testEncodeIpv4AddressWithoutValue() throws Exception {
        ConfigAttributeIpv4Address attributeIp4Address = new ConfigAttributeIpv4Address();

        verifyEncodeIpv4AddresBaseAttribute(
                attributeIp4Address,
                CONFIG_ATTR_INTERNAL_IP4_ADDRESS,
                IPV4_ADDRESS_ATTRIBUTE_WITHOUT_VALUE,
                null /*expectedAddress*/);
    }

    @Test
    public void testDecodeIpv4NetmaskWithValue() throws Exception {
        ConfigAttributeIpv4Netmask attribute =
                new ConfigAttributeIpv4Netmask(IPV4_NETMASK.getAddress());

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_NETMASK, attribute.attributeType);
        assertEquals(IPV4_NETMASK, attribute.address);
    }

    @Test
    public void testDecodeIpv4NetmaskWithoutValue() throws Exception {
        ConfigAttributeIpv4Netmask attribute = new ConfigAttributeIpv4Netmask(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_NETMASK, attribute.attributeType);
        assertNull(attribute.address);
    }

    @Test
    public void testEncodeIpv4Netmask() throws Exception {
        ConfigAttributeIpv4Netmask attribute = new ConfigAttributeIpv4Netmask();

        verifyEncodeIpv4AddresBaseAttribute(
                attribute,
                CONFIG_ATTR_INTERNAL_IP4_NETMASK,
                IPV4_NETMASK_ATTRIBUTE_WITHOUT_VALUE,
                null /*expectedAddress*/);
    }

    @Test
    public void testDecodeIpv4DnsWithValue() throws Exception {
        ConfigAttributeIpv4Dns attribute = new ConfigAttributeIpv4Dns(IPV4_DNS.getAddress());

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_DNS, attribute.attributeType);
        assertEquals(IPV4_DNS, attribute.address);
    }

    @Test
    public void testDecodeIpv4DnsWithoutValue() throws Exception {
        ConfigAttributeIpv4Dns attribute = new ConfigAttributeIpv4Dns(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_DNS, attribute.attributeType);
        assertNull(attribute.address);
    }

    @Test
    public void testEncodeIpv4Dns() throws Exception {
        ConfigAttributeIpv4Dns attribute = new ConfigAttributeIpv4Dns();

        verifyEncodeIpv4AddresBaseAttribute(
                attribute,
                CONFIG_ATTR_INTERNAL_IP4_DNS,
                IPV4_DNS_ATTRIBUTE_WITHOUT_VALUE,
                null /*expectedAddress*/);
    }

    @Test
    public void testDecodeIpv4SubnetWithValue() throws Exception {
        ConfigAttributeIpv4Subnet attributeIp4Subnet =
                new ConfigAttributeIpv4Subnet(IPV4_SUBNET_ATTRIBUTE_VALUE);

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_SUBNET, attributeIp4Subnet.attributeType);
        assertEquals(IPV4_LINK_ADDRESS, attributeIp4Subnet.linkAddress);
    }

    @Test
    public void testDecodeIpv4SubnetWithoutValue() throws Exception {
        ConfigAttributeIpv4Subnet attributeIp4Subnet = new ConfigAttributeIpv4Subnet(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP4_SUBNET, attributeIp4Subnet.attributeType);
        assertNull(attributeIp4Subnet.linkAddress);
    }

    @Test
    public void testDecodeIpv4SubnetWithInvalidValue() throws Exception {
        byte[] ipAddress = IPV4_ADDRESS.getAddress();
        ByteBuffer buffer = ByteBuffer.allocate(ipAddress.length * 2);
        buffer.put(ipAddress).put(ipAddress);

        try {
            new ConfigAttributeIpv4Subnet(buffer.array());
            fail("Expected to fail due to invalid netmask.");
        } catch (InvalidSyntaxException expected) {
        }
    }

    @Test
    public void testEncodeIpv4SubnetWithValue() throws Exception {
        ConfigAttributeIpv4Subnet attributeIp4Subnet =
                new ConfigAttributeIpv4Subnet(IPV4_LINK_ADDRESS);

        verifyBuildAndEncodeAttributeCommon(
                attributeIp4Subnet,
                CONFIG_ATTR_INTERNAL_IP4_SUBNET,
                IPV4_SUBNET_ATTRIBUTE_WITH_VALUE);
        assertEquals(IPV4_LINK_ADDRESS, attributeIp4Subnet.linkAddress);
    }

    @Test
    public void testEncodeIpv4SubnetWithoutValue() throws Exception {
        ConfigAttributeIpv4Subnet attributeIp4Subnet = new ConfigAttributeIpv4Subnet();

        verifyBuildAndEncodeAttributeCommon(
                attributeIp4Subnet,
                CONFIG_ATTR_INTERNAL_IP4_SUBNET,
                IPV4_SUBNET_ATTRIBUTE_WITHOUT_VALUE);
        assertNull(attributeIp4Subnet.linkAddress);
    }

    @Test
    public void testNetmaskToPrefixLen() throws Exception {
        for (int i = 0; i < mNetMasks.length; i++) {
            assertEquals(mIpv4PrefixLens[i], ConfigAttribute.netmaskToPrefixLen(mNetMasks[i]));
        }
    }

    @Test
    public void testPrefixToNetmaskBytes() throws Exception {
        for (int i = 0; i < mIpv4PrefixLens.length; i++) {
            assertArrayEquals(
                    mNetMasks[i].getAddress(),
                    ConfigAttribute.prefixToNetmaskBytes(mIpv4PrefixLens[i]));
        }
    }

    @Test
    public void testDecodeIpv6AddressWithValue() throws Exception {
        ConfigAttributeIpv6Address attributeIp6Address =
                new ConfigAttributeIpv6Address(IPV6_ADDRESS_ATTRIBUTE_VALUE);

        assertEquals(CONFIG_ATTR_INTERNAL_IP6_ADDRESS, attributeIp6Address.attributeType);
        assertEquals(IPV6_LINK_ADDRESS, attributeIp6Address.linkAddress);
    }

    @Test
    public void testDecodeIpv6AddressWithoutValue() throws Exception {
        ConfigAttributeIpv6Address attributeIp6Address =
                new ConfigAttributeIpv6Address(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP6_ADDRESS, attributeIp6Address.attributeType);
        assertNull(attributeIp6Address.linkAddress);
    }

    @Test
    public void testDecodeIpv6AddressWithInvalidValue() throws Exception {
        byte[] invalidValue = new byte[] {1};

        try {
            ConfigAttributeIpv6Address attributeIp6Address =
                    new ConfigAttributeIpv6Address(invalidValue);
            fail("Expected to fail due to invalid attribute value");
        } catch (InvalidSyntaxException expected) {
        }
    }

    @Test
    public void testEncodeIpv6AddressWithValue() throws Exception {
        ConfigAttributeIpv6Address attributeIp6Address =
                new ConfigAttributeIpv6Address(IPV6_LINK_ADDRESS);

        verifyEncodeIpv6RangeBaseAttribute(
                attributeIp6Address,
                CONFIG_ATTR_INTERNAL_IP6_ADDRESS,
                IPV6_ADDRESS_ATTRIBUTE_WITH_VALUE,
                IPV6_LINK_ADDRESS);
    }

    @Test
    public void testEncodeIpv6AddressWithoutValue() throws Exception {
        ConfigAttributeIpv6Address attributeIp6Address = new ConfigAttributeIpv6Address();

        verifyEncodeIpv6RangeBaseAttribute(
                attributeIp6Address,
                CONFIG_ATTR_INTERNAL_IP6_ADDRESS,
                IPV6_ADDRESS_ATTRIBUTE_WITHOUT_VALUE,
                null /*expectedLinkAddress*/);
    }

    @Test
    public void testDecodeIpv6SubnetWithValue() throws Exception {
        ConfigAttributeIpv6Subnet attributeIp6Subnet =
                new ConfigAttributeIpv6Subnet(IPV6_SUBNET_ATTRIBUTE_VALUE);

        assertEquals(CONFIG_ATTR_INTERNAL_IP6_SUBNET, attributeIp6Subnet.attributeType);
        assertEquals(IPV6_LINK_ADDRESS, attributeIp6Subnet.linkAddress);
    }

    @Test
    public void testDecodeIpv6SubnetWithoutValue() throws Exception {
        ConfigAttributeIpv6Subnet attributeIp6Subnet = new ConfigAttributeIpv6Subnet(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP6_SUBNET, attributeIp6Subnet.attributeType);
        assertNull(attributeIp6Subnet.linkAddress);
    }

    @Test
    public void testEncodeIpv6SubnetWithValue() throws Exception {
        ConfigAttributeIpv6Subnet attributeIp6Subnet =
                new ConfigAttributeIpv6Subnet(IPV6_LINK_ADDRESS);

        verifyEncodeIpv6RangeBaseAttribute(
                attributeIp6Subnet,
                CONFIG_ATTR_INTERNAL_IP6_SUBNET,
                IPV6_SUBNET_ATTRIBUTE_WITH_VALUE,
                IPV6_LINK_ADDRESS);
    }

    @Test
    public void testEncodeIpv6SubnetWithoutValue() throws Exception {
        ConfigAttributeIpv6Subnet attributeIp6Subnet = new ConfigAttributeIpv6Subnet();

        verifyEncodeIpv6RangeBaseAttribute(
                attributeIp6Subnet,
                CONFIG_ATTR_INTERNAL_IP6_SUBNET,
                IPV6_SUBNET_ATTRIBUTE_WITHOUT_VALUE,
                null /*expectedLinkAddress*/);
    }

    @Test
    public void testDecodeIpv6DnsWithValue() throws Exception {
        ConfigAttributeIpv6Dns attribute = new ConfigAttributeIpv6Dns(IPV6_DNS.getAddress());

        assertEquals(CONFIG_ATTR_INTERNAL_IP6_DNS, attribute.attributeType);
        assertEquals(IPV6_DNS, attribute.address);
    }

    @Test
    public void testDecodeIpv6DnsWithoutValue() throws Exception {
        ConfigAttributeIpv6Dns attribute = new ConfigAttributeIpv6Dns(new byte[0]);

        assertEquals(CONFIG_ATTR_INTERNAL_IP6_DNS, attribute.attributeType);
        assertNull(attribute.address);
    }

    @Test
    public void testEncodeIpv6Dns() throws Exception {
        ConfigAttributeIpv6Dns attribute = new ConfigAttributeIpv6Dns();

        verifyBuildAndEncodeAttributeCommon(
                attribute, CONFIG_ATTR_INTERNAL_IP6_DNS, IPV6_DNS_ATTRIBUTE_WITHOUT_VALUE);
        assertNull(attribute.address);
    }
}
