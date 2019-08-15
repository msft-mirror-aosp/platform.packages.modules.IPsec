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

import static com.android.ike.ikev2.message.IkePayload.PayloadType;

import android.annotation.IntDef;
import android.annotation.Nullable;
import android.util.Pair;

import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.IkeInternalException;
import com.android.ike.ikev2.exceptions.IkeProtocolException;
import com.android.ike.ikev2.exceptions.InvalidMessageIdException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.exceptions.UnsupportedCriticalPayloadException;
import com.android.internal.annotations.VisibleForTesting;
import com.android.org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * IkeMessage represents an IKE message.
 *
 * <p>It contains all attributes and provides methods for encoding, decoding, encrypting and
 * decrypting.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public final class IkeMessage {
    private static IIkeMessageHelper sIkeMessageHelper = new IkeMessageHelper();
    // Currently use Bouncy Castle as crypto security provider
    static final Provider SECURITY_PROVIDER = new BouncyCastleProvider();

    // Payload types in this set may be included multiple times within an IKE message. All other
    // payload types can be included at most once.
    private static final Set<Integer> REPEATABLE_PAYLOAD_TYPES = new HashSet<>();

    static {
        REPEATABLE_PAYLOAD_TYPES.add(IkePayload.PAYLOAD_TYPE_CERT);
        REPEATABLE_PAYLOAD_TYPES.add(IkePayload.PAYLOAD_TYPE_CERT_REQUEST);
        REPEATABLE_PAYLOAD_TYPES.add(IkePayload.PAYLOAD_TYPE_NOTIFY);
        REPEATABLE_PAYLOAD_TYPES.add(IkePayload.PAYLOAD_TYPE_DELETE);
        REPEATABLE_PAYLOAD_TYPES.add(IkePayload.PAYLOAD_TYPE_VENDOR);
    }

    public final IkeHeader ikeHeader;
    public final List<IkePayload> ikePayloadList;
    /**
     * Conctruct an instance of IkeMessage. It is called by decode or for building outbound message.
     *
     * @param header the header of this IKE message
     * @param payloadList the list of decoded IKE payloads in this IKE message
     */
    public IkeMessage(IkeHeader header, List<IkePayload> payloadList) {
        ikeHeader = header;
        ikePayloadList = payloadList;
    }

    /**
     * Get security provider for IKE library
     *
     * <p>Use BouncyCastleProvider as the default security provider.
     *
     * @return the security provider of IKE library.
     */
    public static Provider getSecurityProvider() {
        // TODO: Move this getter out of IKE message package since not only this package uses it.
        return SECURITY_PROVIDER;
    }

    /**
     * Decode unencrypted IKE message body and create an instance of IkeMessage.
     *
     * <p>This method catches all RuntimeException during decoding incoming IKE packet.
     *
     * @param expectedMsgId the expected message ID to validate against.
     * @param header the IKE header that is decoded but not validated.
     * @param inputPacket the byte array contains the whole IKE message.
     * @return the decoding result.
     */
    public static DecodeResult decode(int expectedMsgId, IkeHeader header, byte[] inputPacket) {
        return sIkeMessageHelper.decode(expectedMsgId, header, inputPacket);
    }

    /**
     * Decrypt and decode encrypted IKE message body and create an instance of IkeMessage.
     *
     * @param expectedMsgId the expected message ID to validate against.
     * @param integrityMac the negotiated integrity algorithm.
     * @param decryptCipher the negotiated encryption algorithm.
     * @param ikeSaRecord ikeSaRecord where this packet is sent on.
     * @param ikeHeader header of IKE packet.
     * @param packet IKE packet as a byte array.
     * @return the decoding result.
     */
    public static DecodeResult decode(
            int expectedMsgId,
            @Nullable IkeMacIntegrity integrityMac,
            IkeCipher decryptCipher,
            IkeSaRecord ikeSaRecord,
            IkeHeader ikeHeader,
            byte[] packet) {
        return sIkeMessageHelper.decode(
                expectedMsgId, integrityMac, decryptCipher, ikeSaRecord, ikeHeader, packet);
    }

    private static List<IkePayload> decodePayloadList(
            @PayloadType int firstPayloadType, boolean isResp, byte[] unencryptedPayloads)
            throws IkeProtocolException {
        ByteBuffer inputBuffer = ByteBuffer.wrap(unencryptedPayloads);
        int currentPayloadType = firstPayloadType;
        // For supported payload
        List<IkePayload> supportedPayloadList = new LinkedList<>();
        // For unsupported critical payload
        List<Integer> unsupportedCriticalPayloadList = new LinkedList<>();

        // For marking the existence of supported payloads in this message.
        HashSet<Integer> supportedTypesFoundSet = new HashSet<>();

        while (currentPayloadType != IkePayload.PAYLOAD_TYPE_NO_NEXT) {
            Pair<IkePayload, Integer> pair =
                    IkePayloadFactory.getIkePayload(currentPayloadType, isResp, inputBuffer);
            IkePayload payload = pair.first;

            if (!(payload instanceof IkeUnsupportedPayload)) {
                int type = payload.payloadType;
                if (!supportedTypesFoundSet.add(type) && !REPEATABLE_PAYLOAD_TYPES.contains(type)) {
                    throw new InvalidSyntaxException(
                            "It is not allowed to have multiple payloads with payload type: "
                                    + type);
                }

                supportedPayloadList.add(payload);
            } else if (payload.isCritical) {
                unsupportedCriticalPayloadList.add(payload.payloadType);
            }
            // Simply ignore unsupported uncritical payload.

            currentPayloadType = pair.second;
        }

        if (inputBuffer.remaining() > 0) {
            throw new InvalidSyntaxException(
                    "Malformed IKE Payload: Unexpected bytes at the end of packet.");
        }

        if (unsupportedCriticalPayloadList.size() > 0) {
            throw new UnsupportedCriticalPayloadException(unsupportedCriticalPayloadList);
        }

        // TODO: Verify that for all status notification payloads, only
        // NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP and NOTIFY_TYPE_IPCOMP_SUPPORTED can be included
        // multiple times in a request message. There is not a clear number restriction for
        // error notification payloads.

        return supportedPayloadList;
    }

    /**
     * Encode unencrypted IKE message.
     *
     * @return encoded IKE message in byte array.
     */
    public byte[] encode() {
        return sIkeMessageHelper.encode(this);
    }

    /**
     * Encrypt and encode packet.
     *
     * @param integrityMac the negotiated integrity algorithm.
     * @param encryptCipher the negotiated encryption algortihm.
     * @param ikeSaRecord the ikeSaRecord where this packet is sent on.
     * @return encoded IKE message in byte array.
     */
    public byte[] encryptAndEncode(
            @Nullable IkeMacIntegrity integrityMac,
            IkeCipher encryptCipher,
            IkeSaRecord ikeSaRecord) {
        return sIkeMessageHelper.encryptAndEncode(integrityMac, encryptCipher, ikeSaRecord, this);
    }

    /**
     * Encode all payloads to a byte array.
     *
     * @return byte array contains all encoded payloads
     */
    private byte[] encodePayloads() {
        if (ikePayloadList.isEmpty()) {
            return new byte[0];
        }

        int payloadLengthSum = 0;
        for (IkePayload payload : ikePayloadList) {
            payloadLengthSum += payload.getPayloadLength();
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(payloadLengthSum);

        for (int i = 0; i < ikePayloadList.size() - 1; i++) {
            ikePayloadList
                    .get(i)
                    .encodeToByteBuffer(ikePayloadList.get(i + 1).payloadType, byteBuffer);
        }
        ikePayloadList
                .get(ikePayloadList.size() - 1)
                .encodeToByteBuffer(IkePayload.PAYLOAD_TYPE_NO_NEXT, byteBuffer);

        return byteBuffer.array();
    }

    /** Package */
    @VisibleForTesting
    byte[] attachEncodedHeader(byte[] encodedIkeBody) {
        ByteBuffer outputBuffer =
                ByteBuffer.allocate(IkeHeader.IKE_HEADER_LENGTH + encodedIkeBody.length);
        ikeHeader.encodeToByteBuffer(outputBuffer, encodedIkeBody.length);
        outputBuffer.put(encodedIkeBody);
        return outputBuffer.array();
    }

    /**
     * Obtain all payloads with input payload type.
     *
     * <p>This method can be only applied to the payload types that can be included multiple times
     * within an IKE message.
     *
     * @param payloadType the payloadType to look for.
     * @param payloadClass the class of the desired payloads.
     * @return a list of IkePayloads with the payloadType.
     */
    public <T extends IkePayload> List<T> getPayloadListForType(
            @IkePayload.PayloadType int payloadType, Class<T> payloadClass) {
        // STOPSHIP: b/130190639 Notify user the error and close IKE session.
        if (!REPEATABLE_PAYLOAD_TYPES.contains(payloadType)) {
            throw new IllegalArgumentException(
                    "Received unexpected payloadType: "
                            + payloadType
                            + " that can be included at most once within an IKE message.");
        }

        return IkePayload.getPayloadListForTypeInProvidedList(
                payloadType, payloadClass, ikePayloadList);
    }

    /**
     * Obtain the payload with the input payload type.
     *
     * <p>This method can be only applied to the payload type that can be included at most once
     * within an IKE message.
     *
     * @param payloadType the payloadType to look for.
     * @param payloadClass the class of the desired payload.
     * @return the IkePayload with the payloadType.
     */
    public <T extends IkePayload> T getPayloadForType(
            @IkePayload.PayloadType int payloadType, Class<T> payloadClass) {
        // STOPSHIP: b/130190639 Notify user the error and close IKE session.
        if (REPEATABLE_PAYLOAD_TYPES.contains(payloadType)) {
            throw new IllegalArgumentException(
                    "Received unexpected payloadType: "
                            + payloadType
                            + " that may be included multiple times within an IKE message.");
        }

        return IkePayload.getPayloadForTypeInProvidedList(
                payloadType, payloadClass, ikePayloadList);
    }

    /**
     * Checks if this Request IkeMessage was a DPD message
     *
     * <p>An IKE message is a DPD request iff the message was encrypted (has a SK payload) and there
     * were no payloads within the SK payload (or outside the SK payload).
     */
    public boolean isDpdRequest() {
        return !ikeHeader.isResponseMsg
                && ikePayloadList.isEmpty()
                && ikeHeader.nextPayloadType == IkePayload.PAYLOAD_TYPE_SK;
    }

    /**
     * IIkeMessageHelper provides interface for decoding, encoding and processing IKE packet.
     *
     * <p>IkeMessageHelper exists so that the interface is injectable for testing.
     */
    @VisibleForTesting
    public interface IIkeMessageHelper {
        /**
         * Encode IKE message.
         *
         * @param ikeMessage message need to be encoded.
         * @return encoded IKE message in byte array.
         */
        byte[] encode(IkeMessage ikeMessage);

        /**
         * Encrypt and encode IKE message.
         *
         * @param integrityMac the negotiated integrity algorithm.
         * @param encryptCipher the negotiated encryption algortihm.
         * @param ikeSaRecord the ikeSaRecord where this packet is sent on.
         * @param ikeMessage message need to be encoded.
         * @return encoded IKE message in byte array.
         */
        byte[] encryptAndEncode(
                @Nullable IkeMacIntegrity integrityMac,
                IkeCipher encryptCipher,
                IkeSaRecord ikeSaRecord,
                IkeMessage ikeMessage);

        // TODO: Return DecodeResult when decoding unencrypted message
        /**
         * Decode unencrypted packet.
         *
         * @param expectedMsgId the expected message ID to validate against.
         * @param ikeHeader header of IKE packet.
         * @param packet IKE packet as a byte array.
         * @return the decoding result.
         */
        DecodeResult decode(int expectedMsgId, IkeHeader ikeHeader, byte[] packet);

        /**
         * Decrypt and decode packet.
         *
         * @param expectedMsgId the expected message ID to validate against.
         * @param integrityMac the negotiated integrity algorithm.
         * @param decryptCipher the negotiated encryption algorithm.
         * @param ikeSaRecord ikeSaRecord where this packet is sent on.
         * @param ikeHeader header of IKE packet.
         * @param packet IKE packet as a byte array.
         * @return the decoding result.
         */
        DecodeResult decode(
                int expectedMsgId,
                @Nullable IkeMacIntegrity integrityMac,
                IkeCipher decryptCipher,
                IkeSaRecord ikeSaRecord,
                IkeHeader ikeHeader,
                byte[] packet);
    }

    /** IkeMessageHelper provides methods for decoding, encoding and processing IKE packet. */
    public static final class IkeMessageHelper implements IIkeMessageHelper {
        @Override
        public byte[] encode(IkeMessage ikeMessage) {
            byte[] encodedIkeBody = ikeMessage.encodePayloads();
            return ikeMessage.attachEncodedHeader(encodedIkeBody);
        }

        @Override
        public byte[] encryptAndEncode(
                @Nullable IkeMacIntegrity integrityMac,
                IkeCipher encryptCipher,
                IkeSaRecord ikeSaRecord,
                IkeMessage ikeMessage) {
            return encryptAndEncode(
                    ikeMessage.ikeHeader,
                    ikeMessage.ikePayloadList.isEmpty()
                            ? IkePayload.PAYLOAD_TYPE_NO_NEXT
                            : ikeMessage.ikePayloadList.get(0).payloadType,
                    ikeMessage.encodePayloads(),
                    integrityMac,
                    encryptCipher,
                    ikeSaRecord.getOutboundIntegrityKey(),
                    ikeSaRecord.getOutboundEncryptionKey());
        }

        private byte[] encryptAndEncode(
                IkeHeader ikeHeader,
                @PayloadType int firstPayload,
                byte[] unencryptedPayloads,
                @Nullable IkeMacIntegrity integrityMac,
                IkeCipher encryptCipher,
                byte[] integrityKey,
                byte[] encryptKey) {
            IkeSkPayload skPayload =
                    new IkeSkPayload(
                            ikeHeader,
                            firstPayload,
                            unencryptedPayloads,
                            integrityMac,
                            encryptCipher,
                            integrityKey,
                            encryptKey);

            ByteBuffer outputBuffer =
                    ByteBuffer.allocate(IkeHeader.IKE_HEADER_LENGTH + skPayload.getPayloadLength());
            ikeHeader.encodeToByteBuffer(outputBuffer, skPayload.getPayloadLength());
            skPayload.encodeToByteBuffer(firstPayload, outputBuffer);

            return outputBuffer.array();
        }

        @Override
        public DecodeResult decode(int expectedMsgId, IkeHeader header, byte[] inputPacket) {
            try {
                if (header.messageId != expectedMsgId) {
                    throw new InvalidMessageIdException(header.messageId);
                }

                header.checkInboundValidOrThrow(inputPacket.length);

                byte[] unencryptedPayloads =
                        Arrays.copyOfRange(
                                inputPacket, IkeHeader.IKE_HEADER_LENGTH, inputPacket.length);
                List<IkePayload> supportedPayloadList =
                        decodePayloadList(
                                header.nextPayloadType, header.isResponseMsg, unencryptedPayloads);
                return new DecodeResult(
                        DECODE_STATUS_OK,
                        new IkeMessage(header, supportedPayloadList),
                        null /*ikeException*/);
            } catch (NegativeArraySizeException | BufferUnderflowException e) {
                // Invalid length error when parsing payload bodies.
                return new DecodeResult(
                        DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE,
                        null /*ikeMessage*/,
                        new InvalidSyntaxException("Malformed IKE Payload"));
            } catch (IkeProtocolException e) {
                return new DecodeResult(
                        DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE, null /*ikeMessage*/, e);
            }
        }

        @Override
        public DecodeResult decode(
                int expectedMsgId,
                @Nullable IkeMacIntegrity integrityMac,
                IkeCipher decryptCipher,
                IkeSaRecord ikeSaRecord,
                IkeHeader ikeHeader,
                byte[] packet) {
            return decode(
                    expectedMsgId,
                    ikeHeader,
                    packet,
                    integrityMac,
                    decryptCipher,
                    ikeSaRecord.getInboundIntegrityKey(),
                    ikeSaRecord.getInboundDecryptionKey());
        }

        private DecodeResult decode(
                int expectedMsgId,
                IkeHeader header,
                byte[] inputPacket,
                @Nullable IkeMacIntegrity integrityMac,
                IkeCipher decryptCipher,
                byte[] integrityKey,
                byte[] decryptKey) {

            if (header.nextPayloadType != IkePayload.PAYLOAD_TYPE_SK) {
                // TODO: b/123372339 Handle message containing unprotected payloads.
                throw new UnsupportedOperationException("Message contains unprotected payloads");
            }

            // Validate security parameters.
            Pair<IkeSkPayload, Integer> pair;
            try {
                if (header.messageId != expectedMsgId) {
                    throw new InvalidMessageIdException(header.messageId);
                }
                pair =
                        IkePayloadFactory.getIkeSkPayload(
                                false /*isSkf*/,
                                inputPacket,
                                integrityMac,
                                decryptCipher,
                                integrityKey,
                                decryptKey);

                // TODO: Support decoding IkeSkfPayload
            } catch (NegativeArraySizeException | BufferUnderflowException e) {
                return new DecodeResult(
                        DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE,
                        null /*ikeMessage*/,
                        new InvalidSyntaxException("Malformed IKE Payload"));
            } catch (GeneralSecurityException e) {
                return new DecodeResult(
                        DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE,
                        null /*ikeMessage*/,
                        new IkeInternalException(e));
            } catch (IkeException e) {
                return new DecodeResult(
                        DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE, null /*ikeMessage*/, e);
            }

            // Check is there is protocol error in this IKE message.
            try {
                IkeSkPayload skPayload = pair.first;
                int firstPayloadType = pair.second;

                List<IkePayload> supportedPayloadList =
                        decodePayloadList(
                                firstPayloadType,
                                header.isResponseMsg,
                                skPayload.getUnencryptedData());

                header.checkInboundValidOrThrow(inputPacket.length);
                return new DecodeResult(
                        DECODE_STATUS_OK,
                        new IkeMessage(header, supportedPayloadList),
                        null /*ikeException*/);
            } catch (NegativeArraySizeException | BufferUnderflowException e) {
                // Invalid length error when parsing payload bodies.
                return new DecodeResult(
                        DECODE_STATUS_PROTECTED_ERROR_MESSAGE,
                        null /*ikeMessage*/,
                        new InvalidSyntaxException("Malformed IKE Payload"));
            } catch (IkeProtocolException e) {
                return new DecodeResult(
                        DECODE_STATUS_PROTECTED_ERROR_MESSAGE, null /*ikeMessage*/, e);
            }
        }
    }

    /** Status to describe the result of decoding an inbound IKE message. */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        DECODE_STATUS_OK,
        DECODE_STATUS_PROTECTED_ERROR_MESSAGE,
        DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE
    })
    public @interface DecodeStatus {}

    /** Represents a message that has been successfuly (decrypted and) decoded. */
    public static final int DECODE_STATUS_OK = 0;
    /** Represents a crypto protected message with correct message ID but has parsing error. */
    public static final int DECODE_STATUS_PROTECTED_ERROR_MESSAGE = 1;
    /**
     * Represents an unencrypted message with parsing error, an encrypted message with
     * authentication or decryption error, or any message with wrong message ID.
     */
    public static final int DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE = 2;

    /** This class represents a result of decoding an IKE message. */
    public static class DecodeResult {
        // TODO: Extend this class to support IKE fragmentation.

        public final int status;
        public final IkeMessage ikeMessage;
        public final IkeException ikeException;

        /** Construct an instance of DecodeResult. */
        public DecodeResult(int status, IkeMessage ikeMessage, IkeException ikeException) {
            this.status = status;
            this.ikeMessage = ikeMessage;
            this.ikeException = ikeException;
        }
    }

    /**
     * For setting mocked IIkeMessageHelper for testing
     *
     * @param helper the mocked IIkeMessageHelper
     */
    public static void setIkeMessageHelper(IIkeMessageHelper helper) {
        sIkeMessageHelper = helper;
    }
}
