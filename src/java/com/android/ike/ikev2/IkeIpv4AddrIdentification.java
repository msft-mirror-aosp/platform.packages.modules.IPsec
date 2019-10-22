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

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Objects;

/** IkeIpv4AddrIdentification represents ID information in IPv4 address ID type. */
public final class IkeIpv4AddrIdentification extends IkeIdentification {
    public final Inet4Address ipv4Address;

    /**
     * Construct an instance of IkeIpv4AddrIdentification from a decoded inbound packet.
     *
     * @param ipv4AddrBytes IPv4 address in byte array.
     * @throws AuthenticationFailedException for decoding bytes error.
     */
    public IkeIpv4AddrIdentification(byte[] ipv4AddrBytes) throws AuthenticationFailedException {
        super(ID_TYPE_IPV4_ADDR);
        try {
            ipv4Address = (Inet4Address) (Inet4Address.getByAddress(ipv4AddrBytes));
        } catch (ClassCastException | UnknownHostException e) {
            throw new AuthenticationFailedException(e);
        }
    }

    /**
     * Construct an instance of IkeIpv4AddrIdentification with user provided IPv4 address for
     * building outbound packet.
     *
     * @param address user provided IPv4 address
     */
    public IkeIpv4AddrIdentification(@NonNull Inet4Address address) {
        super(ID_TYPE_IPV4_ADDR);
        ipv4Address = address;
    }

    @Override
    public int hashCode() {
        return Objects.hash(idType, ipv4Address);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IkeIpv4AddrIdentification)) return false;

        return ipv4Address.equals(((IkeIpv4AddrIdentification) o).ipv4Address);
    }

    /**
     * Retrieve the byte-representation of the IPv4 address.
     *
     * @return the byte-representation of the IPv4 address.
     */
    @Override
    public byte[] getEncodedIdData() {
        return ipv4Address.getAddress();
    }
}
