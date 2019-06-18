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

package com.android.ike.eap.message;

import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.ByteBuffer;

/**
 * EapSimAttribute represents a single EAP-SIM Attribute.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186#section-10">RFC 4186, EAP-SIM Authentication,
 * Section 10</a>
 */
public abstract class EapSimAttribute {
    protected static final int LENGTH_SCALING = 4;

    public static final int SKIPPABLE_ATTRIBUTE_RANGE_START = 128;

    // EAP non-Skippable Attribute values defined by IANA
    // https://www.iana.org/assignments/eapsimaka-numbers/eapsimaka-numbers.xhtml
    public static final int EAP_AT_RAND = 1;
    public static final int EAP_AT_PADDING = 6;
    public static final int EAP_AT_NONCE_MT = 7;
    public static final int EAP_AT_PERMANENT_ID_REQ = 10;
    public static final int EAP_AT_MAC = 11;
    public static final int EAP_AT_NOTIFICATION = 12;
    public static final int EAP_AT_ANY_ID_REQ = 13;
    public static final int EAP_AT_IDENTITY = 14;
    public static final int EAP_AT_VERSION_LIST = 15;
    public static final int EAP_AT_SELECTED_VERSION = 16;
    public static final int EAP_AT_FULLATH_ID_REQ = 17;
    public static final int EAP_AT_COUNTER = 19;
    public static final int EAP_AT_COUNTER_TOO_SMALL = 20;
    public static final int EAP_AT_NONCE_S = 21;
    public static final int EAP_AT_CLIENT_ERROR_CODE = 22;

    // EAP Skippable Attribute values defined by IANA
    // https://www.iana.org/assignments/eapsimaka-numbers/eapsimaka-numbers.xhtml
    public static final int EAP_AT_IV = 129;
    public static final int EAP_AT_ENCR_DATA = 130;
    public static final int EAP_AT_NEXT_PSEUDONYM = 132;
    public static final int EAP_AT_NEXT_REAUTH_ID = 133;
    public static final int EAP_AT_RESULT_IND = 135;

    public final int attributeType;
    public final int lengthInBytes;

    protected EapSimAttribute(int attributeType, int lengthInBytes)
            throws EapSimInvalidAttributeException {
        this.attributeType = attributeType;
        this.lengthInBytes = lengthInBytes;

        if (lengthInBytes % LENGTH_SCALING != 0) {
            throw new EapSimInvalidAttributeException("Attribute length must be multiple of 4");
        }
    }

    /**
     * Encodes this EapSimAttribute into the given ByteBuffer
     *
     * @param byteBuffer the ByteBuffer that this instance will be written to
     */
    public void encode(ByteBuffer byteBuffer) {
        byteBuffer.put((byte) attributeType);
        byteBuffer.put((byte) (lengthInBytes / LENGTH_SCALING));
    }

    /**
     * EapSimUnsupportedAttribute represents any unsupported, skippable EAP-SIM attribute.
     */
    public static class EapSimUnsupportedAttribute extends EapSimAttribute {
        // Attribute Type (1B) + Attribute Length (1B) = 2B Header
        private static final int HEADER_BYTES = 2;

        public final byte[] data;

        public EapSimUnsupportedAttribute(int attributeType, int lengthInBytes,
                ByteBuffer byteBuffer) throws EapSimInvalidAttributeException {
            super(attributeType, lengthInBytes);

            // Attribute not supported, but remaining attribute still needs to be saved
            int remainingBytes = lengthInBytes - HEADER_BYTES;
            data = new byte[remainingBytes];
            byteBuffer.get(data);
        }

        @VisibleForTesting
        public EapSimUnsupportedAttribute(int attributeType, int lengthInBytes, byte[] data)
                throws EapSimInvalidAttributeException {
            super(attributeType, lengthInBytes);
            this.data = data;
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            super.encode(byteBuffer);
            byteBuffer.put(data);
        }
    }
}
