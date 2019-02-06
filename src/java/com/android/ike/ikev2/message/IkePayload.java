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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * IkePayload is an abstract class that represents the common information for all IKE payload types.
 *
 * <p>Each types of IKE payload should implement its own subclass with its own decoding and encoding
 * logic.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.2">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public abstract class IkePayload {
    /** Length of a generic IKE payload header */
    public static final int GENERIC_HEADER_LENGTH = 4;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        PAYLOAD_TYPE_NO_NEXT,
        PAYLOAD_TYPE_SA,
        PAYLOAD_TYPE_KE,
        PAYLOAD_TYPE_NONCE,
        PAYLOAD_TYPE_NOTIFY,
        PAYLOAD_TYPE_VENDOR,
        PAYLOAD_TYPE_SK
    })
    public @interface PayloadType {}

    /** No Next Payload */
    public static final int PAYLOAD_TYPE_NO_NEXT = 0;
    /** Security Association Payload */
    public static final int PAYLOAD_TYPE_SA = 33;
    /** Key Exchange Payload */
    public static final int PAYLOAD_TYPE_KE = 34;
    /** Nonce Payload */
    public static final int PAYLOAD_TYPE_NONCE = 40;
    /** Notify Payload */
    public static final int PAYLOAD_TYPE_NOTIFY = 41;
    /** VENDOR Payload */
    public static final int PAYLOAD_TYPE_VENDOR = 43;
    /** Encrypted and Authenticated Payload */
    public static final int PAYLOAD_TYPE_SK = 46;

    // TODO: List all payload types.

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        PROTOCOL_ID_RESERVED,
        PROTOCOL_ID_IKE,
        PROTOCOL_ID_AH,
        PROTOCOL_ID_ESP,
    })
    public @interface ProtocolId {}

    public static final int PROTOCOL_ID_RESERVED = 0;
    public static final int PROTOCOL_ID_CURRENT_IKE_SA = PROTOCOL_ID_RESERVED;
    public static final int PROTOCOL_ID_IKE = 1;
    public static final int PROTOCOL_ID_AH = 2;
    public static final int PROTOCOL_ID_ESP = 3;

    public static final byte SPI_LEN_NOT_INCLUDED = 0;
    public static final byte SPI_LEN_IPSEC = 4;
    public static final byte SPI_LEN_IKE = 8;

    public final int payloadType;
    public final boolean isCritical;

    /**
     * Construct a instance of IkePayload in the context of a IkePayloadFactory.
     *
     * <p>It should be overrided by subclass of IkePayload
     *
     * @param payload the payload type. All supported types will fall in {@link
     *     IkePayload.PayloadType}
     * @param critical indicates if this payload is critical. Ignore it when payload type is
     *     supported.
     */
    IkePayload(int payload, boolean critical) {
        payloadType = payload;
        isCritical = critical;
    }
}
