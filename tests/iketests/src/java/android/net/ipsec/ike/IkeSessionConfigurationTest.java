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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import android.net.InetAddresses;

import com.android.internal.net.ipsec.ike.message.IkeConfigPayload;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Pcscf;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Pcscf;

import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public final class IkeSessionConfigurationTest {
    private static final Inet4Address PCSCF_IPV4_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.100"));
    private static final Inet6Address PCSCF_IPV6_ADDRESS =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:db8::1"));

    private static final IkeSessionConnectionInfo IKE_CONNECT_INFO =
            mock(IkeSessionConnectionInfo.class);

    @Test
    public void testBuildWithoutPcscfAddresses() {
        IkeSessionConfiguration config =
                new IkeSessionConfiguration(IKE_CONNECT_INFO, null /*configPayload*/);
        assertEquals(IKE_CONNECT_INFO, config.getIkeSessionConnectionInfo());
    }

    @Test
    public void testBuildWithPcscfAddresses() {
        List<ConfigAttribute> attributeList = new LinkedList<>();
        attributeList.add(new ConfigAttributeIpv4Pcscf(PCSCF_IPV4_ADDRESS));
        attributeList.add(new ConfigAttributeIpv6Pcscf(PCSCF_IPV6_ADDRESS));

        IkeConfigPayload configPayload = new IkeConfigPayload(true /*isReply*/, attributeList);

        IkeSessionConfiguration config =
                new IkeSessionConfiguration(IKE_CONNECT_INFO, configPayload);

        assertEquals(IKE_CONNECT_INFO, config.getIkeSessionConnectionInfo());
        assertEquals(
                Arrays.asList(PCSCF_IPV4_ADDRESS, PCSCF_IPV6_ADDRESS), config.getPcscfServers());
    }

    @Test
    public void testBuildWithoutConnectionInfo() {
        try {
            new IkeSessionConfiguration(null /*ikeConnInfo*/, null /*configPayload*/);
            fail("Expected to fail due to null value ikeConnInfo");
        } catch (NullPointerException expected) {

        }
    }
}
