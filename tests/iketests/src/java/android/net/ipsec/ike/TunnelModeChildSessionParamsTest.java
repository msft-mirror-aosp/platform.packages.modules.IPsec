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

import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_ADDRESS;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_DHCP;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_DNS;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_NETMASK;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_ADDRESS;
import static com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_DNS;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.net.InetAddresses;
import android.util.SparseArray;

import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;

import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;

public final class TunnelModeChildSessionParamsTest {
    private static final int NUM_TS = 1;

    private static final int IP6_PREFIX_LEN = 64;

    private static final int INVALID_ADDR_FAMILY = 5;

    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.100"));
    private static final Inet6Address IPV6_ADDRESS =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:db8::1"));

    private static final Inet4Address IPV4_DNS_SERVER =
            (Inet4Address) (InetAddresses.parseNumericAddress("8.8.8.8"));
    private static final Inet6Address IPV6_DNS_SERVER =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:4860:4860::8888"));

    private static final Inet4Address IPV4_DHCP_SERVER =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.200"));
    private ChildSaProposal mSaProposal;

    @Before
    public void setup() {
        mSaProposal =
                new ChildSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12,
                                SaProposal.KEY_LEN_AES_128)
                        .build();
    }

    private void verifyCommon(TunnelModeChildSessionParams childParams) {
        assertArrayEquals(new SaProposal[] {mSaProposal}, childParams.getSaProposalsInternal());
        assertEquals(NUM_TS, childParams.getLocalTrafficSelectorsInternal().length);
        assertEquals(NUM_TS, childParams.getRemoteTrafficSelectorsInternal().length);
        assertFalse(childParams.isTransportMode());
    }

    private void verifyAttrTypes(
            SparseArray expectedAttrCntMap, TunnelModeChildSessionParams childParams) {
        ConfigAttribute[] configAttributes = childParams.getConfigurationAttributesInternal();

        SparseArray<Integer> atrrCntMap = expectedAttrCntMap.clone();

        for (int i = 0; i < configAttributes.length; i++) {
            int attType = configAttributes[i].attributeType;
            assertNotNull(atrrCntMap.get(attType));

            atrrCntMap.put(attType, atrrCntMap.get(attType) - 1);
            if (atrrCntMap.get(attType) == 0) atrrCntMap.remove(attType);
        }

        assertEquals(0, atrrCntMap.size());
    }

    @Test
    public void testBuildChildSessionParamsWithoutConfigReq() {
        TunnelModeChildSessionParams childParams =
                new TunnelModeChildSessionParams.Builder().addSaProposal(mSaProposal).build();

        verifyCommon(childParams);
        assertEquals(0, childParams.getConfigurationAttributesInternal().length);
    }

    @Test
    public void testBuildChildSessionParamsWithAddressReq() {
        TunnelModeChildSessionParams childParams =
                new TunnelModeChildSessionParams.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalAddressRequest(AF_INET)
                        .addInternalAddressRequest(AF_INET6)
                        .addInternalAddressRequest(AF_INET6)
                        .addInternalAddressRequest(IPV4_ADDRESS)
                        .addInternalAddressRequest(IPV6_ADDRESS, IP6_PREFIX_LEN)
                        .build();

        verifyCommon(childParams);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, 2);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP6_ADDRESS, 3);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_NETMASK, 1);

        verifyAttrTypes(expectedAttrCntMap, childParams);
    }

    @Test
    public void testBuildChildSessionParamsWithDnsServerReq() {
        TunnelModeChildSessionParams childParams =
                new TunnelModeChildSessionParams.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalDnsServerRequest(AF_INET)
                        .addInternalDnsServerRequest(AF_INET6)
                        .addInternalDnsServerRequest(IPV4_DNS_SERVER)
                        .addInternalDnsServerRequest(IPV6_DNS_SERVER)
                        .build();

        verifyCommon(childParams);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_DNS, 2);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP6_DNS, 2);

        verifyAttrTypes(expectedAttrCntMap, childParams);
    }

    @Test
    public void testBuildChildSessionParamsWithDhcpServerReq() {
        TunnelModeChildSessionParams childParams =
                new TunnelModeChildSessionParams.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalDhcpServerRequest(AF_INET)
                        .addInternalDhcpServerRequest(AF_INET)
                        .addInternalDhcpServerRequest(AF_INET)
                        .addInternalDhcpServerRequest(IPV4_DHCP_SERVER)
                        .build();

        verifyCommon(childParams);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_DHCP, 4);

        verifyAttrTypes(expectedAttrCntMap, childParams);
    }

    @Test
    public void testBuildChildSessionParamsWithDhcp6SeverReq() {
        try {
            new TunnelModeChildSessionParams.Builder()
                    .addSaProposal(mSaProposal)
                    .addInternalDhcpServerRequest(AF_INET6)
                    .addInternalDhcpServerRequest(AF_INET6)
                    .addInternalDhcpServerRequest(AF_INET6)
                    .build();
            fail("Expected to fail because DHCP6 is not supported.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildChildSessionParamsWithInvalidDhcpReq() {
        try {
            new TunnelModeChildSessionParams.Builder()
                    .addSaProposal(mSaProposal)
                    .addInternalDhcpServerRequest(INVALID_ADDR_FAMILY)
                    .build();
            fail("Expected to fail due to invalid address family value");
        } catch (IllegalArgumentException expected) {

        }
    }
}

