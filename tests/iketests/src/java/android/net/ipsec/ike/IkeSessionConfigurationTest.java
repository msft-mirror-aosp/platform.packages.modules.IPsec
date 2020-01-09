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

import android.net.InetAddresses;

import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Pcscf;
import com.android.internal.net.test.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Pcscf;

import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public final class IkeSessionConfigurationTest {
    private static final Inet4Address IPV4_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.100"));

    private static final Inet6Address IPV6_ADDRESS =
            (Inet6Address) (InetAddresses.parseNumericAddress("2001:db8::1"));

    @Test
    public void testGetPcscfAddresses() {
        List<ConfigAttribute> attributeList = new LinkedList<>();
        attributeList.add(new ConfigAttributeIpv4Pcscf(IPV4_ADDRESS));
        attributeList.add(new ConfigAttributeIpv6Pcscf(IPV6_ADDRESS));

        IkeConfigPayload configPayload = new IkeConfigPayload(true /*isReply*/, attributeList);

        IkeSessionConfiguration config = new IkeSessionConfiguration(configPayload);
        assertEquals(Arrays.asList(IPV4_ADDRESS, IPV6_ADDRESS), config.getPcscfAddresses());
    }
}
