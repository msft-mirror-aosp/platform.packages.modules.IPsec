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

import com.android.ike.eap.exceptions.EapSimInvalidAtPaddingException;
import com.android.ike.eap.exceptions.EapSimInvalidAtRandException;
import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * EapSimAttribute represents a single EAP-SIM Attribute.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186#section-10">RFC 4186, EAP-SIM Authentication,
 * Section 10</a>
 */
public abstract class EapSimAttribute {
    static final int LENGTH_SCALING = 4;
    private static final int MIN_ATTR_LENGTH = 4;

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
    public static final int EAP_AT_FULLAUTH_ID_REQ = 17;
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
    public abstract void encode(ByteBuffer byteBuffer);

    protected void encodeAttributeHeader(ByteBuffer byteBuffer) {
        byteBuffer.put((byte) attributeType);
        byteBuffer.put((byte) (lengthInBytes / LENGTH_SCALING));
    }

    void consumePadding(int bytesUsed, ByteBuffer byteBuffer) {
        int paddingRemaining = lengthInBytes - bytesUsed;
        byteBuffer.get(new byte[paddingRemaining]);
    }

    void addPadding(int bytesUsed, ByteBuffer byteBuffer) {
        int paddingNeeded = lengthInBytes - bytesUsed;
        byteBuffer.put(new byte[paddingNeeded]);
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
            encodeAttributeHeader(byteBuffer);
            byteBuffer.put(data);
        }
    }

    /**
     * AtVersionList represents the AT_VERSION_LIST attribute defined in RFC 4186 Section 10.2
     */
    public static class AtVersionList extends EapSimAttribute {
        private static final int BYTES_PER_VERSION = 2;

        public final List<Integer> versions = new ArrayList<>();

        public AtVersionList(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_VERSION_LIST, lengthInBytes);

            // number of bytes used to represent list (RFC 4186 Section 10.2)
            int bytesInList = Short.toUnsignedInt(byteBuffer.getShort());
            if (bytesInList % BYTES_PER_VERSION != 0) {
                throw new EapSimInvalidAttributeException(
                        "Actual Version List Length must be multiple of 2");
            }

            int numVersions =  bytesInList / BYTES_PER_VERSION;
            for (int i = 0; i < numVersions; i++) {
                versions.add(Short.toUnsignedInt(byteBuffer.getShort()));
            }

            int bytesUsed = MIN_ATTR_LENGTH + (BYTES_PER_VERSION * versions.size());
            consumePadding(bytesUsed, byteBuffer);
        }

        @VisibleForTesting
        public AtVersionList(int lengthInBytes, int... versions)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_VERSION_LIST, lengthInBytes);
            for (int version : versions) {
                this.versions.add(version);
            }
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);

            byteBuffer.putShort((short) (versions.size() * BYTES_PER_VERSION));
            for (int i : versions) {
                byteBuffer.putShort((short) i);
            }

            int bytesUsed = MIN_ATTR_LENGTH + (BYTES_PER_VERSION * versions.size());
            addPadding(bytesUsed, byteBuffer);
        }
    }

    /**
     * AtSelectedVersion represents the AT_SELECTED_VERSION attribute defined in RFC 4186 Section
     * 10.3
     */
    public static class AtSelectedVersion extends EapSimAttribute {
        private static final int LENGTH = LENGTH_SCALING;

        public final int selectedVersion;

        public AtSelectedVersion(int lengthInBytes, int selectedVersion)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_SELECTED_VERSION, LENGTH);
            this.selectedVersion = selectedVersion;

            if (lengthInBytes != LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.putShort((short) selectedVersion);
        }
    }

    /**
     * AtNonceMt represents the AT_NONCE_MT attribute defined in RFC 4186 Section 10.4
     */
    public static class AtNonceMt extends EapSimAttribute {
        private static final int LENGTH = 5 * LENGTH_SCALING;
        private static final int NONCE_MT_LENGTH = 16;
        private static final int RESERVED_BYTES = 2;

        public final byte[] nonceMt = new byte[NONCE_MT_LENGTH];

        public AtNonceMt(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_NONCE_MT, LENGTH);
            if (lengthInBytes != LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }

            // next two bytes are reserved (RFC 4186 Section 10.4)
            byteBuffer.get(new byte[RESERVED_BYTES]);
            byteBuffer.get(nonceMt);
        }

        @VisibleForTesting
        public AtNonceMt(byte[] nonceMt) throws EapSimInvalidAttributeException {
            super(EAP_AT_NONCE_MT, LENGTH);
            for (int i = 0; i < nonceMt.length; i++) {
                this.nonceMt[i] = nonceMt[i];
            }
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.put(new byte[RESERVED_BYTES]);
            byteBuffer.put(nonceMt);
        }
    }

    private abstract static class AtIdReq extends EapSimAttribute {
        private static final int ATTR_LENGTH = LENGTH_SCALING;
        private static final int RESERVED_BYTES = 2;

        protected AtIdReq(int lengthInBytes, int attributeType, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(attributeType, ATTR_LENGTH);

            if (lengthInBytes != ATTR_LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }

            // next two bytes are reserved (RFC 4186 Section 10.5-10.7)
            byteBuffer.get(new byte[RESERVED_BYTES]);
        }

        @VisibleForTesting
        protected AtIdReq(int attributeType) throws EapSimInvalidAttributeException {
            super(attributeType, ATTR_LENGTH);
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.put(new byte[RESERVED_BYTES]);
        }
    }

    /**
     * AtPermanentIdReq represents the AT_PERMANENT_ID_REQ attribute defined in RFC 4186 Section
     * 10.5
     */
    public static class AtPermanentIdReq extends AtIdReq {
        public AtPermanentIdReq(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(lengthInBytes, EAP_AT_PERMANENT_ID_REQ, byteBuffer);
        }

        @VisibleForTesting
        public AtPermanentIdReq() throws EapSimInvalidAttributeException {
            super(EAP_AT_PERMANENT_ID_REQ);
        }
    }

    /**
     * AtAnyIdReq represents the AT_ANY_ID_REQ attribute defined in RFC 4186 Section 10.6
     */
    public static class AtAnyIdReq extends AtIdReq {
        public AtAnyIdReq(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(lengthInBytes, EAP_AT_ANY_ID_REQ, byteBuffer);
        }

        @VisibleForTesting
        public AtAnyIdReq() throws EapSimInvalidAttributeException {
            super(EAP_AT_ANY_ID_REQ);
        }
    }

    /**
     * AtFullauthIdReq represents the AT_FULLAUTH_ID_REQ attribute defined in RFC 4186 Section 10.7
     */
    public static class AtFullauthIdReq extends AtIdReq {
        public AtFullauthIdReq(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(lengthInBytes, EAP_AT_FULLAUTH_ID_REQ, byteBuffer);
        }

        @VisibleForTesting
        public AtFullauthIdReq() throws EapSimInvalidAttributeException {
            super(EAP_AT_FULLAUTH_ID_REQ);
        }
    }

    /**
     * AtIdentity represents the AT_IDENTITY attribute defined in RFC 4186 Section 10.8
     */
    public static class AtIdentity extends EapSimAttribute {
        public final byte[] identity;

        public AtIdentity(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_IDENTITY, lengthInBytes);

            int identityLength = Short.toUnsignedInt(byteBuffer.getShort());
            identity = new byte[identityLength];
            byteBuffer.get(identity);

            int bytesUsed = MIN_ATTR_LENGTH + identityLength;
            consumePadding(bytesUsed, byteBuffer);
        }

        @VisibleForTesting
        public AtIdentity(int lengthInBytes, byte[] identity)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_IDENTITY, lengthInBytes);
            this.identity = identity;
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.putShort((short) identity.length);
            byteBuffer.put(identity);

            int bytesUsed = MIN_ATTR_LENGTH + identity.length;
            addPadding(bytesUsed, byteBuffer);
        }
    }

    /**
     * AtRand represents the AT_RAND attribute defined in RFC 4186 Section 10.9
     */
    public static class AtRand extends EapSimAttribute {
        private static final int RAND_LENGTH = 16;
        private static final int RESERVED_BYTES = 2;
        private static final int MIN_RANDS = 2;
        private static final int MAX_RANDS = 3;

        public final List<byte[]> rands = new ArrayList<>(MAX_RANDS);

        public AtRand(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_RAND, lengthInBytes);

            // next two bytes are reserved (RFC 4186 Section 10.9)
            byteBuffer.get(new byte[RESERVED_BYTES]);

            int numRands = (lengthInBytes - MIN_ATTR_LENGTH) / RAND_LENGTH;
            if (!isValidNumRands(numRands)) {
                throw new EapSimInvalidAtRandException("Unexpected number of rands: " + numRands);
            }

            for (int i = 0; i < numRands; i++) {
                byte[] rand = new byte[RAND_LENGTH];
                byteBuffer.get(rand);

                // check for rand being unique (RFC 4186 Section 10.9)
                for (int j = 0; j < i; j++) {
                    byte[] otherRand = rands.get(j);
                    if (Arrays.equals(rand, otherRand)) {
                        throw new EapSimInvalidAttributeException("Received two identical RANDs");
                    }
                }
                rands.add(rand);
            }
        }

        @VisibleForTesting
        public AtRand(int lengthInBytes, byte[]... rands) throws EapSimInvalidAttributeException {
            super(EAP_AT_RAND, lengthInBytes);

            if (!isValidNumRands(rands.length)) {
                throw new EapSimInvalidAtRandException("Unexpected number of rands: "
                        + rands.length);
            }
            for (byte[] rand : rands) {
                this.rands.add(rand);
            }
        }

        private boolean isValidNumRands(int numRands) {
            // numRands is valid iff 2 <= numRands <= 3
            return MIN_RANDS <= numRands && numRands <= MAX_RANDS;
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.put(new byte[RESERVED_BYTES]);

            for (byte[] rand : rands) {
                byteBuffer.put(rand);
            }
        }
    }

    /**
     * AtPadding represents the AT_PADDING attribute defined in RFC 4186 Section 10.12
     */
    public static class AtPadding extends EapSimAttribute {
        private static final int ATTR_HEADER = 2;

        public AtPadding(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_PADDING, lengthInBytes);

            int remainingBytes = lengthInBytes - ATTR_HEADER;
            for (int i = 0; i < remainingBytes; i++) {
                // Padding must be checked to all be 0x00 bytes (RFC 4186 Section 10.12)
                if (byteBuffer.get() != 0) {
                    throw new EapSimInvalidAtPaddingException("Padding bytes must all be 0x00");
                }
            }
        }

        @VisibleForTesting
        public AtPadding(int lengthInBytes) throws EapSimInvalidAttributeException {
            super(EAP_AT_PADDING, lengthInBytes);
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);

            addPadding(ATTR_HEADER, byteBuffer);
        }
    }

    /**
     * AtMac represents the AT_MAC attribute defined in RFC 4186 Section 10.14
     */
    public static class AtMac extends EapSimAttribute {
        private static final int ATTR_LENGTH = 5 * LENGTH_SCALING;
        private static final int MAC_LENGTH = 4 * LENGTH_SCALING;
        private static final int RESERVED_BYTES = 2;

        public final byte[] mac;

        public AtMac(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_MAC, lengthInBytes);

            if (lengthInBytes != ATTR_LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }

            // next two bytes are reserved (RFC 4186 Section 10.14)
            byteBuffer.get(new byte[RESERVED_BYTES]);

            mac = new byte[MAC_LENGTH];
            byteBuffer.get(mac);
        }

        // Used for calculating MACs. Per RFC 4186 Section 10.14, the MAC should be calculated over
        // the entire packet, with the value field of the MAC attribute set to zero.
        public AtMac() throws EapSimInvalidAttributeException {
            super(EAP_AT_MAC, ATTR_LENGTH);
            mac = new byte[MAC_LENGTH];
        }

        public AtMac(byte[] mac) throws EapSimInvalidAttributeException {
            super(EAP_AT_MAC, ATTR_LENGTH);
            this.mac = mac;

            if (mac.length != MAC_LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid length for MAC");
            }
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.put(new byte[RESERVED_BYTES]);
            byteBuffer.put(mac);
        }
    }

    /**
     * AtCounter represents the AT_COUNTER attribute defined in RFC 4186 Section 10.15
     */
    public static class AtCounter extends EapSimAttribute {
        private static final int ATTR_LENGTH = LENGTH_SCALING;

        public final int counter;

        public AtCounter(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_COUNTER, lengthInBytes);

            if (lengthInBytes != ATTR_LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }

            this.counter = Short.toUnsignedInt(byteBuffer.getShort());
        }

        @VisibleForTesting
        public AtCounter(int counter) throws EapSimInvalidAttributeException {
            super(EAP_AT_COUNTER, ATTR_LENGTH);
            this.counter = counter;
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.putShort((short) counter);
        }
    }


    /**
     * AtCounterTooSmall represents the AT_COUNTER_TOO_SMALL attribute defined in RFC 4186 Section
     * 10.16
     */
    public static class AtCounterTooSmall extends EapSimAttribute {
        private static final int ATTR_LENGTH = LENGTH_SCALING;
        private static final int ATTR_HEADER = 2;

        public AtCounterTooSmall(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_COUNTER_TOO_SMALL, lengthInBytes);

            if (lengthInBytes != ATTR_LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }
            consumePadding(ATTR_HEADER, byteBuffer);
        }

        public AtCounterTooSmall() throws EapSimInvalidAttributeException {
            super(EAP_AT_COUNTER_TOO_SMALL, ATTR_LENGTH);
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            addPadding(ATTR_HEADER, byteBuffer);
        }
    }

    /**
     * AtNonceS represents the AT_NONCE_S attribute defined in RFC 4186 Section 10.17
     *
     * <p>This Nonce is generated by the server and used for fast re-authentication only.
     */
    public static class AtNonceS extends EapSimAttribute {
        private static final int ATTR_LENGTH = 5 * LENGTH_SCALING;
        private static final int NONCE_S_LENGTH = 4 * LENGTH_SCALING;
        private static final int RESERVED_BYTES = 2;

        public final byte[] nonceS;

        public AtNonceS(int lengthInBytes, ByteBuffer byteBuffer)
                throws EapSimInvalidAttributeException {
            super(EAP_AT_NONCE_S, lengthInBytes);

            if (lengthInBytes != ATTR_LENGTH) {
                throw new EapSimInvalidAttributeException("Invalid Length specified");
            }

            // next two bytes are reserved (RFC 4186 Section 10.17)
            byteBuffer.get(new byte[RESERVED_BYTES]);

            nonceS = new byte[NONCE_S_LENGTH];
            byteBuffer.get(nonceS);
        }

        @VisibleForTesting
        public AtNonceS(byte[] nonceS) throws EapSimInvalidAttributeException {
            super(EAP_AT_NONCE_S, ATTR_LENGTH);
            this.nonceS = nonceS;
        }

        @Override
        public void encode(ByteBuffer byteBuffer) {
            encodeAttributeHeader(byteBuffer);
            byteBuffer.put(new byte[RESERVED_BYTES]);
            byteBuffer.put(nonceS);
        }
    }
}
