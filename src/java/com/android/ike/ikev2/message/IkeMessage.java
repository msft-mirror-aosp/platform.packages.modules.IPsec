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

import android.util.Pair;

import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.exceptions.UnsupportedCriticalPayloadException;
import com.android.org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.util.LinkedList;
import java.util.List;

/**
 * IkeMessage represents an IKE message.
 *
 * <p>It contains all attributes and provides methods for encoding, decoding, encrypting and
 * decrypting.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeMessage {

    // Currently use Bouncy Castle as crypto security provider
    static final Provider SECURITY_PROVIDER = new BouncyCastleProvider();

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
     * Decode unenrypted IKE message body and create an instance of IkeMessage.
     *
     * @param header the IKE header that is decoded but not validated
     * @param inputPacket the byte array contains the whole IKE message
     * @throws IkeException if there is any error
     */
    public static IkeMessage decode(IkeHeader header, byte[] inputPacket) throws IkeException {

        header.validate();

        ByteBuffer inputBuffer =
                ByteBuffer.wrap(
                        inputPacket,
                        IkeHeader.IKE_HEADER_LENGTH,
                        inputPacket.length - IkeHeader.IKE_HEADER_LENGTH);
        @PayloadType int currentPayloadType = header.nextPayloadType;
        // For supported payload
        List<IkePayload> supportedPayloadList = new LinkedList<>();
        // For unsupported critical payload
        List<Integer> unsupportedCriticalPayloadList = new LinkedList<>();

        while (currentPayloadType != IkePayload.PAYLOAD_TYPE_NO_NEXT) {
            try {
                Pair<IkePayload, Integer> pair =
                        IkePayloadFactory.getIkePayload(currentPayloadType, inputBuffer);
                IkePayload payload = pair.first;

                if (!(payload instanceof IkeUnsupportedPayload)) {
                    supportedPayloadList.add(payload);
                } else if (payload.isCritical) {
                    unsupportedCriticalPayloadList.add(payload.payloadType);
                }
                // Simply ignore unsupported uncritical payload.

                currentPayloadType = pair.second;
            } catch (NegativeArraySizeException | BufferUnderflowException e) {
                throw new InvalidSyntaxException("Malformed IKE Payload");
            }
        }

        if (unsupportedCriticalPayloadList.size() > 0) {
            throw new UnsupportedCriticalPayloadException(unsupportedCriticalPayloadList);
        }
        return new IkeMessage(header, supportedPayloadList);
    }

    static Provider getProvider() {
        return SECURITY_PROVIDER;
    }
}
