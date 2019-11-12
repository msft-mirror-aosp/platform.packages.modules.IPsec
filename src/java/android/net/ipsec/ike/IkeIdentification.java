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

package android.net.ipsec.ike;

import android.annotation.IntDef;
import android.util.ArraySet;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Set;

/**
 * IkeIdentification is abstract base class that represents the common information for all types of
 * IKE entity identification.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.5">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 * @hide
 */
public abstract class IkeIdentification {
    // Set of supported ID types.
    private static final Set<Integer> SUPPORTED_ID_TYPES;

    /** @hide */
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

    /** @hide */
    public static final int ID_TYPE_IPV4_ADDR = 1;
    /** @hide */
    public static final int ID_TYPE_FQDN = 2;
    /** @hide */
    public static final int ID_TYPE_RFC822_ADDR = 3;
    /** @hide */
    public static final int ID_TYPE_IPV6_ADDR = 5;
    /** @hide */
    public static final int ID_TYPE_DER_ASN1_DN = 9;
    /** @hide */
    public static final int ID_TYPE_DER_ASN1_GN = 10;
    /** @hide */
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

    /** @hide */
    public final int idType;

    /** @hide */
    protected IkeIdentification(@IdType int type) {
        idType = type;
    }

    /**
     * Return the encoded identification data in a byte array.
     *
     * @return the encoded identification data.
     * @hide
     */
    public abstract byte[] getEncodedIdData();
}
