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

package com.android.ike.ikev2.message;

import android.annotation.IntDef;
import android.util.Pair;

import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.internal.annotations.VisibleForTesting;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

/**
 * IkeSaPayload represents a Security Association payload. It contains one or more {@link Proposal}.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeSaPayload extends IkePayload {
    public final List<Proposal> proposalList;
    /**
     * Construct an instance of IkeSaPayload in the context of IkePayloadFactory
     *
     * @param critical indicates if this payload is critical. Ignored in supported payload as
     *     instructed by the RFC 7296.
     * @param payloadBody the encoded payload body in byte array
     */
    IkeSaPayload(boolean critical, byte[] payloadBody) throws IkeException {
        super(IkePayload.PAYLOAD_TYPE_SA, critical);

        ByteBuffer inputBuffer = ByteBuffer.wrap(payloadBody);
        proposalList = new LinkedList<>();
        while (inputBuffer.hasRemaining()) {
            Proposal proposal = Proposal.readFrom(inputBuffer);
            proposalList.add(proposal);
        }
    }

    @VisibleForTesting
    interface TransformDecoder {
        Transform[] decodeTransforms(int count, ByteBuffer inputBuffer) throws IkeException;
    }

    // TODO: Add another constructor for building outbound message.

    /**
     * Proposal represents a set contains cryptograhic algorithms and key generating materials. It
     * contains multiple {@link Transform}.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.1">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     *     <p>Ignore Proposal with unsupported Protocol ID when processing IkeSaPayload
     */
    public static final class Proposal {
        private static final byte LAST_PROPOSAL = 0;
        private static final byte NOT_LAST_PROPOSAL = 2;

        @VisibleForTesting
        static TransformDecoder sTransformDecoder =
                new TransformDecoder() {
                    @Override
                    public Transform[] decodeTransforms(int count, ByteBuffer inputBuffer)
                            throws IkeException {
                        Transform[] transformArray = new Transform[count];
                        for (int i = 0; i < count; i++) {
                            Transform transform = Transform.readFrom(inputBuffer);
                            transformArray[i] = transform;
                        }
                        return transformArray;
                    }
                };

        public final byte number;
        /** All supported protocol will fall into {@link ProtocolId} */
        public final int protocolId;

        public final byte spiSize;
        public final long spi;
        public final Transform[] transformArray;

        @VisibleForTesting
        Proposal(byte number, int protocolId, byte spiSize, long spi, Transform[] transformArray) {
            this.number = number;
            this.protocolId = protocolId;
            this.spiSize = spiSize;
            this.spi = spi;
            this.transformArray = transformArray;
        }

        @VisibleForTesting
        static Proposal readFrom(ByteBuffer inputBuffer) throws IkeException {
            byte isLast = inputBuffer.get();
            if (isLast != LAST_PROPOSAL && isLast != NOT_LAST_PROPOSAL) {
                throw new InvalidSyntaxException(
                        "Invalid value of Last Proposal Substructure: " + isLast);
            }
            // Skip RESERVED byte
            inputBuffer.get();

            int length = Short.toUnsignedInt(inputBuffer.getShort());
            byte number = inputBuffer.get();
            int protocolId = Byte.toUnsignedInt(inputBuffer.get());

            byte spiSize = inputBuffer.get();
            int transformCount = Byte.toUnsignedInt(inputBuffer.get());

            // TODO: Add check: spiSize must be 0 in initial IKE SA negotiation
            // spiSize should be either 8 for IKE or 4 for IPsec.
            long spi = 0;
            switch (spiSize) {
                case 0:
                    // No SPI field here.
                    break;
                case SPI_LEN_IPSEC:
                    spi = Integer.toUnsignedLong(inputBuffer.getInt());
                    break;
                case SPI_LEN_IKE:
                    spi = inputBuffer.getLong();
                    break;
                default:
                    throw new InvalidSyntaxException(
                            "Invalid value of spiSize in Proposal Substructure: " + spiSize);
            }

            Transform[] transformArray =
                    sTransformDecoder.decodeTransforms(transformCount, inputBuffer);

            return new Proposal(number, protocolId, spiSize, spi, transformArray);
        }
        // TODO: Add another contructor for encoding.
    }

    @VisibleForTesting
    interface AttributeDecoder {
        List<Attribute> decodeAttributes(int length, ByteBuffer inputBuffer) throws IkeException;
    }

    /**
     * Transform represents a cryptograhic algorithm. It may contain one or more {@link Attribute}.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     *     <p>Ignore Transform with unsupported type when processing IkeSaPayload
     */
    public static final class Transform {

        @Retention(RetentionPolicy.SOURCE)
        @IntDef({
            TRANSFORM_TYPE_ENCR,
            TRANSFORM_TYPE_PRF,
            TRANSFORM_TYPE_INTEG,
            TRANSFORM_TYPE_DH,
            TRANSFORM_TYPE_ESN
        })
        public @interface TransformType {}

        public static final int TRANSFORM_TYPE_ENCR = 1;
        public static final int TRANSFORM_TYPE_PRF = 2;
        public static final int TRANSFORM_TYPE_INTEG = 3;
        public static final int TRANSFORM_TYPE_DH = 4;
        public static final int TRANSFORM_TYPE_ESN = 5;

        private static final byte LAST_TRANSFORM = 0;
        private static final byte NOT_LAST_TRANSFORM = 3;
        private static final int TRANSFORM_HEADER_LEN = 8;

        // TODO: Add constants for supported algorithms

        @VisibleForTesting
        static AttributeDecoder sAttributeDecoder =
                new AttributeDecoder() {
                    public List<Attribute> decodeAttributes(int length, ByteBuffer inputBuffer)
                            throws IkeException {
                        List<Attribute> list = new LinkedList<>();
                        int parsedLength = TRANSFORM_HEADER_LEN;
                        while (parsedLength < length) {
                            Pair<Attribute, Integer> pair = Attribute.readFrom(inputBuffer);
                            parsedLength += pair.second;
                            list.add(pair.first);
                        }
                        return list;
                    }
                };

        // Only supported type falls into {@link TransformType}
        public final int type;
        public final int id;
        public final List<Attribute> attributeList;

        Transform(int type, int id, List<Attribute> attributeList) {
            this.type = type;
            this.id = id;
            this.attributeList = attributeList;
        }

        @VisibleForTesting
        static Transform readFrom(ByteBuffer inputBuffer) throws IkeException {
            byte isLast = inputBuffer.get();
            if (isLast != LAST_TRANSFORM && isLast != NOT_LAST_TRANSFORM) {
                throw new InvalidSyntaxException(
                        "Invalid value of Last Transform Substructure: " + isLast);
            }

            // Skip RESERVED byte
            inputBuffer.get();

            int length = Short.toUnsignedInt(inputBuffer.getShort());
            int type = Byte.toUnsignedInt(inputBuffer.get());

            // Skip RESERVED byte
            inputBuffer.get();

            int id = Short.toUnsignedInt(inputBuffer.getShort());

            // Decode attributes
            List<Attribute> attributeList = sAttributeDecoder.decodeAttributes(length, inputBuffer);

            return new Transform(type, id, attributeList);
        }

        // TODO: Add another contructor for encoding.
    }

    /**
     * Attribute is for completing the specification of some {@link Transform}.
     *
     * <p>Attribute is either in Type/Value format or Type/Length/Value format. For TV format,
     * Attribute length is always 4 bytes containing value for 2 bytes. While for TLV format,
     * Attribute length is determined by length field.
     *
     * <p>Currently only Key Length type is supported
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.5">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     */
    public static final class Attribute {
        @Retention(RetentionPolicy.SOURCE)
        @IntDef({ATTRIBUTE_TYPE_KEY_LENGTH})
        public @interface AttributeType {}

        // Support only one Attribute type: Key Length. Should use Type/Value format.
        public static final int ATTRIBUTE_TYPE_KEY_LENGTH = 14;

        private static final int LENGTH_FOR_TV = 4;
        private static final int VALUE_SIZE_FOR_TV = 2;

        // Only Key Length type belongs to AttributeType
        public final int type;
        public final byte[] value;

        Attribute(int type, byte[] value) {
            this.type = type;
            this.value = value;
        }

        @VisibleForTesting
        static Pair<Attribute, Integer> readFrom(ByteBuffer inputBuffer) throws IkeException {
            short formatAndType = inputBuffer.getShort();
            int type = formatAndType & 0x7fff;
            int length = 0;
            byte[] value = new byte[0];
            if ((formatAndType & 0x8000) == 0x8000) {
                // Type/Value format
                length = LENGTH_FOR_TV;
                value = new byte[VALUE_SIZE_FOR_TV];
            } else {
                // Type/Length/Value format
                if (type == ATTRIBUTE_TYPE_KEY_LENGTH) {
                    throw new InvalidSyntaxException("Wrong format in Transform Attribute");
                }
                length = Short.toUnsignedInt(inputBuffer.getShort());
                value = new byte[length - LENGTH_FOR_TV];
            }
            inputBuffer.get(value);
            return new Pair(new Attribute(type, value), length);
        }

        // TODO: Add another contructor for encoding.

    }

    /**
     * Encode SA payload to byte array.
     *
     * @param nextPayload type of payload that follows this payload.
     * @return encoded SA payload
     */
    @Override
    byte[] encode(@PayloadType int nextPayload) {
        throw new UnsupportedOperationException(
                "It is not supported to encode a " + getTypeString());
        // TODO: Implement encoding SA payload.
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        return "SA Payload";
    }
}
