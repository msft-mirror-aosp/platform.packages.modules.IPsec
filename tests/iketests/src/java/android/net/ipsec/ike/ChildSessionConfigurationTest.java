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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import android.net.InetAddresses;
import android.net.LinkAddress;

import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Address;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Netmask;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Address;

import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.LinkedList;
import java.util.List;

public final class ChildSessionConfigurationTest {
    private static final int IP4_PREFIX_LEN = 28;
    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.100"));
    private static final Inet4Address IPV4_NETMASK =
            (Inet4Address) (InetAddresses.parseNumericAddress("255.255.255.240"));
    private static final LinkAddress IPV4_LINK_ADDRESS =
            new LinkAddress(IPV4_ADDRESS, IP4_PREFIX_LEN);

    private static final int IP6_PREFIX_LEN = 64;
    private static final Inet6Address IPV6_ADDRESS =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:db8::1"));
    private static final LinkAddress IPV6_LINK_ADDRESS =
            new LinkAddress(IPV6_ADDRESS, IP6_PREFIX_LEN);

    private List mMockInTsList;
    private List mMockOutTsList;

    private ConfigAttributeIpv4Address mIpv4Attr;
    private ConfigAttributeIpv4Netmask mNetmaskAttr;
    private ConfigAttributeIpv6Address mIpv6Attr;

    @Before
    public void setUp() throws Exception {
        mMockInTsList = new LinkedList<IkeTrafficSelector>();
        mMockInTsList.add(mock(IkeTrafficSelector.class));

        mMockOutTsList = new LinkedList<IkeTrafficSelector>();
        mMockOutTsList.add(mock(IkeTrafficSelector.class));
        mMockOutTsList.add(mock(IkeTrafficSelector.class));

        mIpv4Attr = new ConfigAttributeIpv4Address(IPV4_ADDRESS);
        mNetmaskAttr = new ConfigAttributeIpv4Netmask(IPV4_NETMASK.getAddress());
        mIpv6Attr = new ConfigAttributeIpv6Address(IPV6_LINK_ADDRESS);
    }

    private void verifySessionConfigCommon(ChildSessionConfiguration sessionConfig) {
        verifyTsList(mMockInTsList, sessionConfig.getInboundTrafficSelectors());
        verifyTsList(mMockOutTsList, sessionConfig.getOutboundTrafficSelectors());
    }

    private void verifyTsList(
            List<IkeTrafficSelector> expectedList, List<IkeTrafficSelector> tsList) {
        assertEquals(expectedList.size(), tsList.size());
        for (int i = 0; i < expectedList.size(); i++) {
            assertEquals(expectedList.get(i), tsList.get(i));
        }
    }

    @Test
    public void testBuildWithoutConfig() {
        ChildSessionConfiguration sessionConfig =
                new ChildSessionConfiguration(mMockInTsList, mMockOutTsList);

        verifySessionConfigCommon(sessionConfig);
    }

    @Test
    public void testBuildWithNetmaskAttr() {
        List<ConfigAttribute> attributeList = new LinkedList<>();
        attributeList.add(mIpv4Attr);
        attributeList.add(mNetmaskAttr);
        attributeList.add(mIpv6Attr);

        IkeConfigPayload configPayload = new IkeConfigPayload(true /*isReply*/, attributeList);

        ChildSessionConfiguration sessionConfig =
                new ChildSessionConfiguration(mMockInTsList, mMockOutTsList, configPayload);

        verifySessionConfigCommon(sessionConfig);

        List<LinkAddress> expectedInternalAddrList = new LinkedList<>();
        expectedInternalAddrList.add(IPV4_LINK_ADDRESS);
        expectedInternalAddrList.add(IPV6_LINK_ADDRESS);

        assertEquals(expectedInternalAddrList.size(), sessionConfig.getInternalAddresses().size());
        for (int i = 0; i < expectedInternalAddrList.size(); i++) {
            assertEquals(
                    expectedInternalAddrList.get(i), sessionConfig.getInternalAddresses().get(i));
        }
    }

    @Test
    public void testBuildWithoutNetmaskAttr() {
        List<ConfigAttribute> attributeList = new LinkedList<>();
        attributeList.add(mIpv4Attr);
        attributeList.add(mIpv6Attr);

        IkeConfigPayload configPayload = new IkeConfigPayload(true /*isReply*/, attributeList);

        ChildSessionConfiguration sessionConfig =
                new ChildSessionConfiguration(mMockInTsList, mMockOutTsList, configPayload);

        verifySessionConfigCommon(sessionConfig);

        List<LinkAddress> expectedInternalAddrList = new LinkedList<>();
        expectedInternalAddrList.add(new LinkAddress(IPV4_ADDRESS, 32));
        expectedInternalAddrList.add(IPV6_LINK_ADDRESS);

        assertEquals(expectedInternalAddrList.size(), sessionConfig.getInternalAddresses().size());
        for (int i = 0; i < expectedInternalAddrList.size(); i++) {
            assertEquals(
                    expectedInternalAddrList.get(i), sessionConfig.getInternalAddresses().get(i));
        }
    }

    @Test
    public void testBuildWithConfigReq() {
        List<ConfigAttribute> attributeList = new LinkedList<>();
        attributeList.add(mIpv4Attr);
        attributeList.add(mIpv6Attr);

        IkeConfigPayload configPayload = new IkeConfigPayload(false /*isReply*/, attributeList);

        try {
            new ChildSessionConfiguration(mMockInTsList, mMockOutTsList, configPayload);
            fail("Expected to fail because provided config paylaod is not a reply.");
        } catch (IllegalArgumentException expected) {

        }
    }
}
