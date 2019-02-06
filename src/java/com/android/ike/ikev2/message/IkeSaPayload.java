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

import static com.android.ike.ikev2.SaProposal.EncryptionAlgorithm;
import static com.android.ike.ikev2.SaProposal.PseudorandomFunction;

import android.annotation.IntDef;
import android.util.ArraySet;
import android.util.Pair;

import com.android.ike.ikev2.SaProposal;
import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.internal.annotations.VisibleForTesting;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * IkeSaPayload represents a Security Association payload. It contains one or more {@link Proposal}.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeSaPayload extends IkePayload {
    public final List<Proposal> proposalList;
    /**
     * Construct an instance of IkeSaPayload in the context of IkePayloadFactory.
     *
     * @param critical indicates if this payload is critical. Ignored in supported payload as
     *     instructed by the RFC 7296.
     * @param payloadBody the encoded payload body in byte array.
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
     * Proposal represents a set contains cryptographic algorithms and key generating materials. It
     * contains multiple {@link Transform}.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.1">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     *     <p>Proposals with an unrecognized Protocol ID, containing an unrecognized Transform Type
     *     or lacking a necessary Transform Type shall be ignored when processing a received SA
     *     Payload.
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
                            if (transform.isSupported) {
                                transformArray[i] = transform;
                            }
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
        // TODO: Validate this proposal

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
     * Transform is an abstract base class that represents the common information for all Transform
     * types. It may contain one or more {@link Attribute}.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     *     <p>Transforms with unrecognized Transform ID or containing unrecognized Attribute Type
     *     shall be ignored when processing received SA payload.
     */
    public abstract static class Transform {

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
        public final boolean isSupported;

        /** Construct an instance of Transform in the context of {@link SaProposal} */
        protected Transform(int type, int id) {
            this.type = type;
            this.id = id;
            if (!isSupportedTransformId(id)) {
                throw new IllegalArgumentException(
                        "Unsupported " + getTransformTypeString() + " Algorithm ID: " + id);
            }
            this.isSupported = true;
        }

        /** Construct an instance of Transform in the context of {@link Transform} */
        protected Transform(int type, int id, List<Attribute> attributeList) {
            this.type = type;
            this.id = id;
            this.isSupported =
                    isSupportedTransformId(id) && !hasUnrecognizedAttribute(attributeList);
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

            validateAttributeUniqueness(attributeList);

            switch (type) {
                case TRANSFORM_TYPE_ENCR:
                    return new EncryptionTransform(id, attributeList);
                case TRANSFORM_TYPE_PRF:
                    return new PrfTransform(id, attributeList);
                    // TODO: Add Integrity algorithm, DhGroup and ESN
                default:
                    return new UnrecognizedTransform(type, id, attributeList);
            }
        }

        // Throw InvalidSyntaxException if there are multiple Attributes of the same type
        private static void validateAttributeUniqueness(List<Attribute> attributeList)
                throws IkeException {
            Set<Integer> foundTypes = new ArraySet<>();
            for (Attribute attr : attributeList) {
                if (!foundTypes.add(attr.type)) {
                    throw new InvalidSyntaxException(
                            "There are multiple Attributes of the same type. ");
                }
            }
        }

        // Check if this Transform ID is supported.
        protected abstract boolean isSupportedTransformId(int id);

        // Check if there is Attribute with unrecognized type.
        protected boolean hasUnrecognizedAttribute(List<Attribute> attributeList) {
            for (Attribute attr : attributeList) {
                if (attr instanceof UnrecognizedAttribute) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Get Tranform Type as a String.
         *
         * @return Tranform Type as a String.
         */
        public abstract String getTransformTypeString();

        // TODO: Add abstract getTransformIdString() to return specific algorithm/dhGroup name
    }

    // TODO: Implement PrfTransform, IntegrityTransform, DhGroupTransform and EsnTransForm

    /**
     * EncryptionTransform represents an encryption algorithm. It may contain an Atrribute
     * specifying the key length.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     */
    public static final class EncryptionTransform extends Transform {
        private static final int KEY_LEN_UNASSIGNED = 0;

        public final int keyLength;

        @Override
        protected boolean isSupportedTransformId(int id) {
            return SaProposal.isSupportedEncryptionAlgorithm(id);
        }

        /**
         * Contruct an instance of EncryptionTransform in the context of {@link SaProposal} with
         * fixed key length.
         *
         * @param id the IKE standard Transform ID.
         */
        public EncryptionTransform(@EncryptionAlgorithm int id) {
            this(id, KEY_LEN_UNASSIGNED);
        }

        /**
         * Contruct an instance of EncryptionTransform in the context of {@link SaProposal} with
         * variable key length.
         *
         * @param id the IKE standard Transform ID.
         * @param keyLength the specified key length of this encryption algorithm.
         */
        public EncryptionTransform(@EncryptionAlgorithm int id, int keyLength) {
            super(Transform.TRANSFORM_TYPE_ENCR, id);

            this.keyLength = keyLength;
            try {
                validateKeyLength();
            } catch (InvalidSyntaxException e) {
                throw new IllegalArgumentException(e.message);
            }
        }

        /**
         * Contruct an instance of EncryptionTransform in the context of abstract class {@link
         * Transform}.
         *
         * @param id the IKE standard Transform ID.
         * @param attributeList the decoded list of Attribute.
         * @throws InvalidSyntaxException for syntax error.
         */
        protected EncryptionTransform(int id, List<Attribute> attributeList)
                throws InvalidSyntaxException {
            super(Transform.TRANSFORM_TYPE_ENCR, id, attributeList);
            if (!isSupported) {
                keyLength = KEY_LEN_UNASSIGNED;
            } else {
                if (attributeList.size() == 0) {
                    keyLength = KEY_LEN_UNASSIGNED;
                } else {
                    KeyLengthAttribute attr = getKeyLengthAttribute(attributeList);
                    keyLength = attr.keyLength;
                }
                validateKeyLength();
            }
        }

        private KeyLengthAttribute getKeyLengthAttribute(List<Attribute> attributeList) {
            for (Attribute attr : attributeList) {
                if (attr.type == Attribute.ATTRIBUTE_TYPE_KEY_LENGTH) {
                    return (KeyLengthAttribute) attr;
                }
            }
            throw new IllegalArgumentException("Cannot find Attribute with Key Length type");
        }

        private void validateKeyLength() throws InvalidSyntaxException {
            switch (id) {
                case SaProposal.ENCRYPTION_ALGORITHM_3DES:
                    if (keyLength != KEY_LEN_UNASSIGNED) {
                        throw new InvalidSyntaxException(
                                "Must not set Key Length value for this "
                                        + getTransformTypeString()
                                        + " Algorithm ID: "
                                        + id);
                    }
                    return;
                case SaProposal.ENCRYPTION_ALGORITHM_AES_CBC:
                    /* fall through */
                case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8:
                    /* fall through */
                case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12:
                    /* fall through */
                case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16:
                    if (keyLength == KEY_LEN_UNASSIGNED) {
                        throw new InvalidSyntaxException(
                                "Must set Key Length value for this "
                                        + getTransformTypeString()
                                        + " Algorithm ID: "
                                        + id);
                    }
                    if (keyLength != SaProposal.KEY_LEN_AES_128
                            && keyLength != SaProposal.KEY_LEN_AES_192
                            && keyLength != SaProposal.KEY_LEN_AES_256) {
                        throw new InvalidSyntaxException(
                                "Invalid key length for this "
                                        + getTransformTypeString()
                                        + " Algorithm ID: "
                                        + id);
                    }
                    return;
                default:
                    // Won't hit here.
                    throw new IllegalArgumentException(
                            "Unrecognized Encryption Algorithm ID: " + id);
            }
        }

        @Override
        public String getTransformTypeString() {
            return "Encryption Algorithm";
        }
    }

    /**
     * PrfTransform represents an pseudorandom function.
     *
     * <p>Currently it does not have any supported {@link Attribute}.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key
     *     Exchange Protocol Version 2 (IKEv2).
     */
    public static final class PrfTransform extends Transform {
        @Override
        protected boolean isSupportedTransformId(int id) {
            return SaProposal.isSupportedPseudorandomFunction(id);
        }

        /**
         * Contruct an instance of PrfTransform in the context of {@link SaProposal}.
         *
         * @param id the IKE standard Transform ID.
         */
        public PrfTransform(@PseudorandomFunction int id) {
            super(Transform.TRANSFORM_TYPE_PRF, id);
        }

        /**
         * Contruct an instance of PrfTransform in the context of abstract class {@link Transform}.
         *
         * @param id the IKE standard Transform ID.
         * @param attributeList the decoded list of Attribute.
         * @throws InvalidSyntaxException for syntax error.
         */
        protected PrfTransform(int id, List<Attribute> attributeList)
                throws InvalidSyntaxException {
            super(Transform.TRANSFORM_TYPE_PRF, id, attributeList);
        }

        @Override
        public String getTransformTypeString() {
            return "Pseudorandom Function";
        }
    }

    /**
     * UnrecognizedTransform represents a Transform with unrecognized Transform Type.
     *
     * <p>Proposals containing an UnrecognizedTransform should be ignored.
     */
    protected static final class UnrecognizedTransform extends Transform {

        @Override
        protected boolean isSupportedTransformId(int id) {
            return false;
        }

        protected UnrecognizedTransform(int type, int id, List<Attribute> attributeList) {
            super(type, id, attributeList);
        }

        /**
         * Return Tranform Type of Unrecognized Transform as a String.
         *
         * @return Tranform Type of Unrecognized Transform as a String.
         */
        @Override
        public String getTransformTypeString() {
            return "Unrecognized Transform Type";
        }
    }

    /**
     * Attribute is an abtract base class for completing the specification of some {@link
     * Transform}.
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
    public abstract static class Attribute {
        @Retention(RetentionPolicy.SOURCE)
        @IntDef({ATTRIBUTE_TYPE_KEY_LENGTH})
        public @interface AttributeType {}

        // Support only one Attribute type: Key Length. Should use Type/Value format.
        public static final int ATTRIBUTE_TYPE_KEY_LENGTH = 14;

        private static final int LENGTH_FOR_TV = 4;
        private static final int VALUE_SIZE_FOR_TV = 2;

        // Only Key Length type belongs to AttributeType
        public final int type;

        /** Construct an instance of an Attribute when decoding message. */
        protected Attribute(int type) {
            this.type = type;
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

            switch (type) {
                case ATTRIBUTE_TYPE_KEY_LENGTH:
                    return new Pair(new KeyLengthAttribute(value), length);
                default:
                    return new Pair(new UnrecognizedAttribute(type, value), length);
            }
        }
    }

    /** KeyLengthAttribute represents a Key Length type Attribute */
    public static final class KeyLengthAttribute extends Attribute {
        public final int keyLength;

        protected KeyLengthAttribute(byte[] value) {
            this(Short.toUnsignedInt(ByteBuffer.wrap(value).getShort()));
        }

        protected KeyLengthAttribute(int keyLength) {
            super(ATTRIBUTE_TYPE_KEY_LENGTH);
            this.keyLength = keyLength;
        }
    }

    /**
     * UnrecognizedAttribute represents a Attribute with unrecoginzed Attribute Type.
     *
     * <p>Transforms containing UnrecognizedAttribute should be ignored.
     */
    protected static final class UnrecognizedAttribute extends Attribute {
        protected UnrecognizedAttribute(int type, byte[] value) {
            super(type);
        }
    }

    /**
     * Encode SA payload to ByteBUffer.
     *
     * @param nextPayload type of payload that follows this payload.
     * @param byteBuffer destination ByteBuffer that stores encoded payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        throw new UnsupportedOperationException(
                "It is not supported to encode a " + getTypeString());
        // TODO: Implement encoding SA payload.
    }

    /**
     * Get entire payload length.
     *
     * @return entire payload length.
     */
    @Override
    protected int getPayloadLength() {
        throw new UnsupportedOperationException(
                "It is not supported to get payload length of " + getTypeString());
        // TODO: Implement this method for SA payload.
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
