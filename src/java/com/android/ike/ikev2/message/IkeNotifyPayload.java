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

import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;

/**
 * IkeNotifyPayload represents a Notify Payload.
 *
 * <p>As instructed by RFC 7296, for IKE SA concerned Notify Payload, Protocol ID and SPI Size must
 * be zero. Unrecognized notify message type must be ignored but should be logged.
 *
 * <p>Critical bit for this payload must be ignored in received packet and must not be set in
 * outbound packet.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296">RFC 7296, Internet Key Exchange Protocol
 *     Version 2 (IKEv2).
 */
public final class IkeNotifyPayload extends IkePayload {

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        NOTIFY_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD,
        NOTIFY_TYPE_INVALID_MAJOR_VERSION,
        NOTIFY_TYPE_INVALID_SYNTAX,
        NOTIFY_TYPE_INVALID_SELECTORS,
        NOTIFY_TYPE_CHILD_SA_NOT_FOUND,
        NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP,
        NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP,
        NOTIFY_TYPE_REKEY_SA
    })
    public @interface NotifyType {}

    public static final int NOTIFY_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD = 1;
    public static final int NOTIFY_TYPE_INVALID_MAJOR_VERSION = 5;
    public static final int NOTIFY_TYPE_INVALID_SYNTAX = 7;
    public static final int NOTIFY_TYPE_INVALID_SELECTORS = 39;
    public static final int NOTIFY_TYPE_CHILD_SA_NOT_FOUND = 44;

    public static final int NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP = 16388;
    public static final int NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP = 16389;
    public static final int NOTIFY_TYPE_REKEY_SA = 16393;
    // TODO: List all supported notify types.

    private static final int NOTIFY_HEADER_LEN = 4;

    public final int protocolId;
    public final byte spiSize;
    public final int notifyType;
    public final int spi;
    public final byte[] notifyData;

    /**
     * Construct an instance of IkeNotifyPayload in the context of IkePayloadFactory
     *
     * @param critical indicates if this payload is critical. Ignored in supported payload as
     *     instructed by the RFC 7296.
     * @param payloadBody payload body in byte array
     * @throws IkeException if there is any error
     */
    IkeNotifyPayload(boolean isCritical, byte[] payloadBody) throws IkeException {
        super(PAYLOAD_TYPE_NOTIFY, isCritical);
        ByteBuffer inputBuffer = ByteBuffer.wrap(payloadBody);

        protocolId = Byte.toUnsignedInt(inputBuffer.get());
        spiSize = inputBuffer.get();
        notifyType = Short.toUnsignedInt(inputBuffer.getShort());

        // Validate syntax of spiSize, protocolId and notifyType
        if (spiSize == SPI_LEN_IPSEC) {
            // For Child SA concerned message
            if (protocolId != PROTOCOL_ID_AH && protocolId != PROTOCOL_ID_ESP) {
                throw new InvalidSyntaxException(
                        "Expected Procotol ID AH(2) or ESP(3): Protocol ID is " + protocolId);
            }

            if (notifyType != NOTIFY_TYPE_INVALID_SELECTORS
                    && notifyType != NOTIFY_TYPE_CHILD_SA_NOT_FOUND) {
                throw new InvalidSyntaxException(
                        "Expected Child SA concerned Notify Type: Notify Type is " + notifyType);
            }

            spi = inputBuffer.getInt();

        } else if (spiSize == SPI_LEN_NOT_INCLUDED) {
            // For IKE SA concerned message
            if (protocolId != PROTOCOL_ID_CURRENT_IKE_SA) {
                throw new InvalidSyntaxException(
                        "Expected Procotol ID for current IKE(0): Protocol ID is " + protocolId);
            }

            if (notifyType == NOTIFY_TYPE_INVALID_SELECTORS
                    || notifyType == NOTIFY_TYPE_CHILD_SA_NOT_FOUND
                    || notifyType == NOTIFY_TYPE_REKEY_SA) {
                throw new InvalidSyntaxException(
                        "Expected IKE SA concerned Notify Type: Notify Type is " + notifyType);
            }
            spi = 0;

        } else {
            throw new InvalidSyntaxException("Invalid SPI Size: " + spiSize);
        }

        notifyData = new byte[payloadBody.length - NOTIFY_HEADER_LEN];
        inputBuffer.get(notifyData);
    }
}
