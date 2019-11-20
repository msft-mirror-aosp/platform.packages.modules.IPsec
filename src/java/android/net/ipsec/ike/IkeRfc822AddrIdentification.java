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

import android.annotation.NonNull;

import java.nio.charset.Charset;
import java.util.Objects;

/**
 * This class represents IKE ID information in fully-qualified RFC 822 email address ID type.
 *
 * @hide
 */
public final class IkeRfc822AddrIdentification extends IkeIdentification {
    private static final Charset UTF8 = Charset.forName("UTF-8");

    /** @hide */
    public final String rfc822Name;

    /**
     * Construct an instance of IkeRfc822AddrIdentification from a decoded inbound packet.
     *
     * <p>All characters in the RFC 822 email address are UTF-8.
     *
     * @param rfc822NameBytes fully-qualified RFC 822 email address in byte array.
     * @hide
     */
    public IkeRfc822AddrIdentification(byte[] rfc822NameBytes) {
        super(ID_TYPE_RFC822_ADDR);
        rfc822Name = new String(rfc822NameBytes, UTF8);
    }

    /**
     * Construct an instance of IkeRfc822AddrIdentification with user provided fully-qualified RFC
     * 822 email address for building outbound packet.
     *
     * <p>rfc822Name will be formatted as UTF-8.
     *
     * @param rfc822Name user provided fully-qualified RFC 822 email address.
     * @hide
     */
    public IkeRfc822AddrIdentification(@NonNull String rfc822Name) {
        super(ID_TYPE_RFC822_ADDR);
        this.rfc822Name = rfc822Name;
    }

    /** @hide */
    @Override
    public int hashCode() {
        return Objects.hash(idType, rfc822Name);
    }

    /** @hide */
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IkeRfc822AddrIdentification)) return false;

        return rfc822Name.equals(((IkeRfc822AddrIdentification) o).rfc822Name);
    }

    /**
     * Retrieve the byte-representation of the the RFC 822 email address.
     *
     * @return the byte-representation of the RFC 822 email address.
     * @hide
     */
    @Override
    public byte[] getEncodedIdData() {
        return rfc822Name.getBytes(UTF8);
    }
}
