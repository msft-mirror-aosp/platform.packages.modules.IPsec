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

/** IkeFqdnIdentification represents ID information using a fully-qualified domain name (FQDN) */
public class IkeFqdnIdentification extends IkeIdentification {
    private static final Charset ASCII = Charset.forName("US-ASCII");

    public final String fqdn;

    /**
     * Construct an instance of IkeFqdnIdentification from a decoded inbound packet.
     *
     * <p>All characters in the FQDN are ASCII.
     *
     * @param fqdnBytes FQDN in byte array.
     */
    public IkeFqdnIdentification(byte[] fqdnBytes) {
        super(ID_TYPE_FQDN);
        fqdn = new String(fqdnBytes, ASCII);
    }

    /**
     * Construct an instance of IkeFqdnIdentification with user provided fully-qualified domain name
     * (FQDN) for building outbound packet.
     *
     * <p>FQDN will be formatted as US-ASCII.
     *
     * @param fqdn user provided fully-qualified domain name (FQDN)
     */
    public IkeFqdnIdentification(@NonNull String fqdn) {
        super(ID_TYPE_FQDN);
        this.fqdn = fqdn;
    }

    @Override
    public int hashCode() {
        return Objects.hash(idType, fqdn);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IkeFqdnIdentification)) return false;

        return fqdn.equals(((IkeFqdnIdentification) o).fqdn);
    }

    /**
     * Retrieve the byte-representation of the FQDN.
     *
     * @return the byte-representation of the FQDN.
     */
    @Override
    public byte[] getEncodedIdData() {
        return fqdn.getBytes(ASCII);
    }
}
