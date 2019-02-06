/*
 * Copyright (C) 2018 The Android Open Source Project
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

import android.annotation.IntDef;
import android.util.ArraySet;

import com.android.ike.ikev2.exceptions.AuthenticationFailedException;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * IkeIdentification is abstract base class that represents the common information for all types of
 * IKE entity identification.
 *
 * <p>IkeIdentification can be user configured or be constructed from an inbound packet.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.5">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public abstract class IkeIdentification {
    // Set of supported ID types.
    private static final Set<Integer> SUPPORTED_ID_TYPES;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        ID_TYPE_IPV4_ADDR,
        ID_TYPE_FQDN,
        ID_TYPE_RFC822_ADDR,
        ID_TYPE_IPV6_ADDR,
        ID_TYPE_DER_ASN1_DN,
        ID_TYPE_DER_ASN1_GN,
        ID_TYPE_KEY_ID
    })
    public @interface IdType {}

    public static final int ID_TYPE_IPV4_ADDR = 1;
    public static final int ID_TYPE_FQDN = 2;
    public static final int ID_TYPE_RFC822_ADDR = 3;
    public static final int ID_TYPE_IPV6_ADDR = 5;
    public static final int ID_TYPE_DER_ASN1_DN = 9;
    public static final int ID_TYPE_DER_ASN1_GN = 10;
    public static final int ID_TYPE_KEY_ID = 11;

    static {
        SUPPORTED_ID_TYPES = new ArraySet();
        SUPPORTED_ID_TYPES.add(ID_TYPE_IPV4_ADDR);
        SUPPORTED_ID_TYPES.add(ID_TYPE_FQDN);
        SUPPORTED_ID_TYPES.add(ID_TYPE_RFC822_ADDR);
        SUPPORTED_ID_TYPES.add(ID_TYPE_IPV6_ADDR);
        SUPPORTED_ID_TYPES.add(ID_TYPE_DER_ASN1_DN);
        SUPPORTED_ID_TYPES.add(ID_TYPE_DER_ASN1_GN);
        SUPPORTED_ID_TYPES.add(ID_TYPE_KEY_ID);
    }

    public final int idType;

    protected IkeIdentification(@IdType int type) {
        idType = type;
    }

    /**
     * Compare this IkeIdentification against specified IkeIdentification.
     *
     * @param ikeId the IkeIdentification to compare against.
     * @return true if two IkeIdentifications are the same; false otherwise.
     */
    public abstract boolean equals(IkeIdentification ikeId);

    /**
     * Return the encoded identification data in a byte array.
     *
     * @return the encoded identification data.
     */
    public abstract byte[] getEncodedIdData();

    // TODO: Add abstract method for encoding.

    /** IkeIpv4AddrIdentification represents ID information in IPv4 address ID type. */
    public static class IkeIpv4AddrIdentification extends IkeIdentification {
        public final Inet4Address ipv4Address;

        /**
         * Construct an instance of IkeIpv4AddrIdentification from decoding an inbound packet.
         *
         * @param ipv4AddrBytes IPv4 address in byte array.
         * @throws AuthenticationFailedException for decoding bytes error.
         */
        public IkeIpv4AddrIdentification(byte[] ipv4AddrBytes)
                throws AuthenticationFailedException {
            super(ID_TYPE_IPV4_ADDR);
            try {
                ipv4Address = (Inet4Address) (Inet4Address.getByAddress(ipv4AddrBytes));
            } catch (UnknownHostException e) {
                throw new AuthenticationFailedException("IP4 address is of illegal length.");
            }
        }

        /**
         * Construct an instance of IkeIpv4AddrIdentification with user provided IPv4 address for
         * building outbound packet.
         *
         * @param address user provided IPv4 address
         */
        public IkeIpv4AddrIdentification(Inet4Address address) {
            super(ID_TYPE_IPV4_ADDR);
            ipv4Address = address;
        }

        /**
         * Compare this IkeIpv4AddrIdentification against specified IkeIdentification.
         *
         * @param ikeId the IkeIdentification to compare against.
         * @return true if IkeIdentifications are the same; false otherwise.
         */
        @Override
        public boolean equals(IkeIdentification ikeId) {
            if (!(ikeId instanceof IkeIpv4AddrIdentification)) return false;

            return ipv4Address.equals(((IkeIpv4AddrIdentification) ikeId).ipv4Address);
        }

        /**
         * Return raw IP address in a byte array.
         *
         * @return the raw IP address in a byte array.
         */
        @Override
        public byte[] getEncodedIdData() {
            return ipv4Address.getAddress();
        }
    }
}
