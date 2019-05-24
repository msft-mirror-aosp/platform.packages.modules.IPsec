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

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;

import com.android.ike.eap.exceptions.EapInvalidPacketLengthException;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.InvalidEapCodeException;
import com.android.ike.eap.exceptions.UnsupportedEapTypeException;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * EapMessage represents an EAP Message.
 *
 * <p>EapMessages will be of type:
 * <ul>
 *     <li>@{link EAP_CODE_REQUEST}</li>
 *     <li>@{link EAP_CODE_RESPONSE}</li>
 *     <li>@{link EAP_CODE_SUCCESS}</li>
 *     <li>@{link EAP_CODE_FAILURE}</li>
 * </ul>
 *
 * Per RFC 3748 Section 4, EAP-Request and EAP-Response packets should be in the format:
 *
 * +-----------------+-----------------+----------------------------------+
 * |    Code (1B)    | Identifier (1B) |           Length (2B)            |
 * +-----------------+-----------------+----------------------------------+
 * |    Type (1B)    |  Type-Data ...
 * +-----------------+-----
 *
 * EAP-Success and EAP-Failure packets should be in the format:
 *
 * +-----------------+-----------------+----------------------------------+
 * |   Code (1B)     | Identifier (1B) |       Length (2B) = '0004'       |
 * +-----------------+-----------------+----------------------------------+
 *
 * Note that Length includes the EAP Header bytes.
 *
 * @see <a href="https://tools.ietf.org/html/rfc3748#section-4">RFC 3748, Extensible Authentication
 * Protocol (EAP)</a>
 */
public class EapMessage {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            EAP_CODE_REQUEST,
            EAP_CODE_RESPONSE,
            EAP_CODE_SUCCESS,
            EAP_CODE_FAILURE
    })
    public @interface EapCode {}

    public static final int EAP_CODE_REQUEST = 1;
    public static final int EAP_CODE_RESPONSE = 2;
    public static final int EAP_CODE_SUCCESS = 3;
    public static final int EAP_CODE_FAILURE = 4;

    public static final int EAP_HEADER_LENGTH = 4;

    @EapCode public final int eapCode;
    public final int eapIdentifier;
    public final int eapLength;
    public final EapData eapData;

    private EapMessage(@EapCode int eapCode, int eapIdentifier, int eapLength,
            @Nullable EapData eapData) throws EapSilentException {
        this.eapCode = eapCode;
        this.eapIdentifier = eapIdentifier;
        this.eapLength = eapLength;
        this.eapData = eapData;

        validate();
    }

    /**
     * Decodes and returns an EapMessage from the given byte array.
     *
     * @param packet byte array containing a byte-encoded EapMessage
     * @return the EapMessage instance representing the given {@param packet}
     * @throws EapSilentException for decoding errors that must be discarded silently
     */
    public static EapMessage decode(@NonNull byte[] packet) throws EapSilentException {
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        int eapCode;
        int eapIdentifier;
        int eapLength;
        EapData eapData;
        try {
            eapCode = Byte.toUnsignedInt(buffer.get());
            eapIdentifier = Byte.toUnsignedInt(buffer.get());
            eapLength = Short.toUnsignedInt(buffer.getShort());

            if (eapCode == EAP_CODE_REQUEST || eapCode == EAP_CODE_RESPONSE) {
                int eapType = Byte.toUnsignedInt(buffer.get());
                if (!EapData.isSupportedEapType(eapType)) {
                    throw new UnsupportedEapTypeException(eapIdentifier,
                            "Unsupported eapType=" + eapType);
                }

                byte[] eapDataBytes = new byte[buffer.remaining()];
                buffer.get(eapDataBytes);
                eapData = new EapData(eapType, eapDataBytes);
            } else {
                eapData = null;
            }
        } catch (BufferUnderflowException ex) {
            throw new EapInvalidPacketLengthException("Packet is missing required values", ex);
        }

        return new EapMessage(eapCode, eapIdentifier, eapLength, eapData);
    }

    /**
     * Converts this EapMessage instance to its byte-encoded representation.
     *
     * @return byte[] representing the byte-encoded EapMessage
     */
    public byte[] encode() {
        // TODO(b/133248540): implement and utilize EapMessage#encode functionality
        return new byte[eapLength];
    }

    private void validate() throws EapSilentException {
        if (eapCode != EAP_CODE_REQUEST
                && eapCode != EAP_CODE_RESPONSE
                && eapCode != EAP_CODE_SUCCESS
                && eapCode != EAP_CODE_FAILURE) {
            throw new InvalidEapCodeException(eapCode);
        }

        int eapDataLength = (eapData == null) ? 0 : eapData.getLength();
        if (eapLength > EAP_HEADER_LENGTH + eapDataLength) {
            throw new EapInvalidPacketLengthException("Packet is shorter than specified length");
        }

        if ((eapCode == EAP_CODE_SUCCESS || eapCode == EAP_CODE_FAILURE)
                && eapLength != EAP_HEADER_LENGTH) {
            throw new EapInvalidPacketLengthException(
                    "EAP Success/Failure packets must be length 4");
        }
    }
}
