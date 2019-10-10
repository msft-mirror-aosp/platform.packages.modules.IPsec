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

package com.android.ike.ikev2;

import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_ADDRESS;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_NETMASK;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_ADDRESS;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.util.SparseArray;

import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttribute;

import libcore.net.InetAddressUtils;

import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;

public final class TunnelModeChildSessionOptionsTest {
    private static final int NUM_TS = 1;

    private static final int IP4_PREFIX_LEN = 32;
    private static final int IP6_PREFIX_LEN = 64;

    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.100"));
    private static final Inet6Address IPV6_ADDRESS =
            (Inet6Address) (InetAddressUtils.parseNumericAddress("2001:db8::1"));

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
            SparseArray exptectedAttrCntMap, TunnelModeChildSessionOptions childOptions) {
        ConfigAttribute[] configAttributes = childOptions.getConfigurationRequests();

        SparseArray<Integer> atrrCntMap = exptectedAttrCntMap.clone();

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

        SparseArray<Integer> exptectedAttrCntMap = new SparseArray<>();
        exptectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, 2);
        exptectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP6_ADDRESS, 3);
        exptectedAttrCntMap.put(CONFIG_ATTR_INTERNAL_IP4_NETMASK, 1);

        verifyAttrTypes(exptectedAttrCntMap, childOptions);
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
}
