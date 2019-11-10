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

package android.net.ipsec.ike;

import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_ADDRESS;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_DHCP;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_DNS;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_NETMASK;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_SUBNET;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_ADDRESS;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_DNS;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_SUBNET;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.util.SparseArray;

import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;

import libcore.net.InetAddressUtils;

import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;

public final class TunnelModeChildSessionOptionsTest {
    private static final int NUM_TS = 1;

    private static final int IP4_PREFIX_LEN = 32;
    private static final int IP6_PREFIX_LEN = 64;

    private static final int INVALID_ADDR_FAMILY = 5;

    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.100"));
    private static final Inet6Address IPV6_ADDRESS =
            (Inet6Address) (InetAddressUtils.parseNumericAddress("2001:db8::1"));

    private static final Inet4Address IPV4_DNS_SERVER =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("8.8.8.8"));
    private static final Inet6Address IPV6_DNS_SERVER =
            (Inet6Address) (InetAddressUtils.parseNumericAddress("2001:4860:4860::8888"));

    private static final Inet4Address IPV4_DHCP_SERVER =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.200"));
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

    private void verifyCommon(TunnelModeChildSessionOptions childOptions) {
        assertArrayEquals(new SaProposal[] {mSaProposal}, childOptions.getSaProposals());
        assertEquals(NUM_TS, childOptions.getLocalTrafficSelectors().length);
        assertEquals(NUM_TS, childOptions.getRemoteTrafficSelectors().length);
        assertFalse(childOptions.isTransportMode());
    }

    private void verifyAttrTypes(
            SparseArray expectedAttrCntMap, TunnelModeChildSessionOptions childOptions) {
        ConfigAttribute[] configAttributes = childOptions.getConfigurationRequests();

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
    public void testBuildChildSessionOptionsWithoutConfigReq() {
        TunnelModeChildSessionOptions childOptions =
                new TunnelModeChildSessionOptions.Builder().addSaProposal(mSaProposal).build();

        verifyCommon(childOptions);
        assertEquals(0, childOptions.getConfigurationRequests().length);
    }

    @Test
    public void testBuildChildSessionOptionsWithAddressReq() {
        TunnelModeChildSessionOptions childOptions =
                new TunnelModeChildSessionOptions.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalAddressRequest(AF_INET, 1)
                        .addInternalAddressRequest(AF_INET6, 2)
                        .addInternalAddressRequest(IPV4_ADDRESS, IP4_PREFIX_LEN)
                        .addInternalAddressRequest(IPV6_ADDRESS, IP6_PREFIX_LEN)
                        .build();

        verifyCommon(childOptions);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, 2);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP6_ADDRESS, 3);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_NETMASK, 1);

        verifyAttrTypes(expectedAttrCntMap, childOptions);
    }

    @Test
    public void testBuildChildSessionOptionsWithInvalidAddressReq() {
        try {
            new TunnelModeChildSessionOptions.Builder()
                    .addSaProposal(mSaProposal)
                    .addInternalAddressRequest(IPV4_ADDRESS, 31)
                    .build();
            fail("Expected to fail due to invalid IPv4 prefix length.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildChildSessionOptionsWithDnsServerReq() {
        TunnelModeChildSessionOptions childOptions =
                new TunnelModeChildSessionOptions.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalDnsServerRequest(AF_INET, 1)
                        .addInternalDnsServerRequest(AF_INET6, 1)
                        .addInternalDnsServerRequest(IPV4_DNS_SERVER)
                        .addInternalDnsServerRequest(IPV6_DNS_SERVER)
                        .build();

        verifyCommon(childOptions);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_DNS, 2);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP6_DNS, 2);

        verifyAttrTypes(expectedAttrCntMap, childOptions);
    }

    @Test
    public void testBuildChildSessionOptionsWithSubnetReq() {
        TunnelModeChildSessionOptions childOptions =
                new TunnelModeChildSessionOptions.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalSubnetRequest(AF_INET, 1)
                        .addInternalSubnetRequest(AF_INET6, 1)
                        .build();

        verifyCommon(childOptions);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_SUBNET, 1);
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP6_SUBNET, 1);

        verifyAttrTypes(expectedAttrCntMap, childOptions);
    }

    @Test
    public void testBuildChildSessionOptionsWithDhcpServerReq() {
        TunnelModeChildSessionOptions childOptions =
                new TunnelModeChildSessionOptions.Builder()
                        .addSaProposal(mSaProposal)
                        .addInternalDhcpServerRequest(AF_INET, 3)
                        .addInternalDhcpServerRequest(IPV4_DHCP_SERVER)
                        .build();

        verifyCommon(childOptions);

        SparseArray<Integer> expectedAttrCntMap = new SparseArray<>();
        expectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_DHCP, 4);

        verifyAttrTypes(expectedAttrCntMap, childOptions);
    }

    @Test
    public void testBuildChildSessionOptionsWithDhcp6SeverReq() {
        try {
            new TunnelModeChildSessionOptions.Builder()
                    .addSaProposal(mSaProposal)
                    .addInternalDhcpServerRequest(AF_INET6, 3)
                    .build();
            fail("Expected to fail because DHCP6 is not supported.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildChildSessionOptionsWithInvalidDhcpReq() {
        try {
            new TunnelModeChildSessionOptions.Builder()
                    .addSaProposal(mSaProposal)
                    .addInternalDhcpServerRequest(INVALID_ADDR_FAMILY, 3)
                    .build();
            fail("Expected to fail due to invalid address family value");
        } catch (IllegalArgumentException expected) {

        }
    }
}

