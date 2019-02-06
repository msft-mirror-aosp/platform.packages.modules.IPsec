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

import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.message.IkePayload.PayloadType;

import java.nio.ByteBuffer;

/**
 * IkeIdPayload represents an Identification Initiator Payload or an Identification Responder
 * Payload.
 *
 * <p>Identification Initiator Payload and Identification Responder Payload have same format but
 * different payload type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.5">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeIdPayload extends IkePayload {
    IkeIdPayload(boolean critical, byte[] payloadBody, boolean isInitiator) throws IkeException {
        super((isInitiator ? PAYLOAD_TYPE_ID_INITIATOR : PAYLOAD_TYPE_ID_RESPONDER), critical);
        // TODO: Decode and validate syntax of payloadBody.
    }

    /**
     * Encode Identification Payload to ByteBuffer.
     *
     * @param nextPayload type of payload that follows this payload.
     * @param byteBuffer destination ByteBuffer that stores encoded payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        throw new UnsupportedOperationException(
                "It is not supported to encode a " + getTypeString());
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
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        switch (payloadType) {
            case PAYLOAD_TYPE_ID_INITIATOR:
                return "Identification Initiator Payload";
            case PAYLOAD_TYPE_ID_RESPONDER:
                return "Identification Responder Payload";
            default:
                // Won't reach here.
                throw new IllegalArgumentException(
                        "Invalid Payload Type for Identification Payload.");
        }
    }
}
