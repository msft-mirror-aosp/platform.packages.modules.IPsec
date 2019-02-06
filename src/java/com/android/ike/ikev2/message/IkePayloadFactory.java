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

import java.nio.ByteBuffer;

/**
 * IkePayloadFactory is used for creating IkePayload according to is type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
final class IkePayloadFactory {
    /**
     * Construct an instance of IkePayload according to its payload type.
     *
     * @param payloadType the current payload type
     * @param input the encoded IKE message body containing all payloads. Position of it will
     *     increment.
     */
    static Pair<IkePayload, Integer> getIkePayload(@PayloadType int payloadType, ByteBuffer input) {
        @PayloadType int nextPayloadType = (int) input.get();
        // read critical bit
        boolean isCritical = ((input.get() & 0x80) == 0x80);

        int payloadLength = Short.toUnsignedInt(input.getShort());
        int bodyLength = payloadLength - IkePayload.GENERIC_HEADER_LENGTH;
        byte[] payloadBody = new byte[bodyLength];
        input.get(payloadBody);

        switch (payloadType) {
                // TODO: Add cases for creating supported payloads.
            default:
                return new Pair(
                        new IkeUnsupportedPayload(payloadType, isCritical), nextPayloadType);
        }
    }
}
