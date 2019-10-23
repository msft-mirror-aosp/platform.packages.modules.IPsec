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

import android.annotation.NonNull;

import com.android.ike.ikev2.exceptions.AuthenticationFailedException;

import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.Objects;

/** IkeIpv6AddrIdentification represents ID information in IPv6 address ID type. */
public class IkeIpv6AddrIdentification extends IkeIdentification {
    public final Inet6Address ipv6Address;

    /**
     * Construct an instance of IkeIpv6AddrIdentification from a decoded inbound packet.
     *
     * @param ipv6AddrBytes IPv6 address in byte array.
     * @throws AuthenticationFailedException for decoding bytes error.
     */
    public IkeIpv6AddrIdentification(byte[] ipv6AddrBytes) throws AuthenticationFailedException {
        super(ID_TYPE_IPV6_ADDR);
        try {
            ipv6Address = (Inet6Address) (Inet6Address.getByAddress(ipv6AddrBytes));
        } catch (ClassCastException | UnknownHostException e) {
            throw new AuthenticationFailedException(e);
        }
    }

    /**
     * Construct an instance of IkeIpv6AddrIdentification with user provided IPv6 address for
     * building outbound packet.
     *
     * @param address user provided IPv6 address
     */
    public IkeIpv6AddrIdentification(@NonNull Inet6Address address) {
        super(ID_TYPE_IPV6_ADDR);
        ipv6Address = address;
    }

    @Override
    public int hashCode() {
        return Objects.hash(idType, ipv6Address);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IkeIpv6AddrIdentification)) return false;

        return ipv6Address.equals(((IkeIpv6AddrIdentification) o).ipv6Address);
    }

    /**
     * Retrieve the byte-representation of the IPv6 address.
     *
     * @return the byte-representation of the IPv6 address.
     */
    @Override
    public byte[] getEncodedIdData() {
        return ipv6Address.getAddress();
    }
}
