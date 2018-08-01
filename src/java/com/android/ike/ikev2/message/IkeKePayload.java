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
 * IkeKePayload represents a Key Exchange payload
 *
 * <p>This class provides methods for generating Diffie-Hellman value and doing Diffie-Hellman
 * exhchange. Upper layer should ignore IkeKePayload with unsupported DH group type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#page-89">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeKePayload extends IkePayload {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({DH_GROUP_1024_BIT_MODP, DH_GROUP_2048_BIT_MODP})
    public @interface DhGroup {}

    public static final int DH_GROUP_1024_BIT_MODP = 2;
    public static final int DH_GROUP_2048_BIT_MODP = 14;

    private static final int KE_HEADER_LEN = 4;
    // Key exchange data length in octets
    private static final int DH_GROUP_1024_BIT_MODP_DATA_LEN = 128;
    private static final int DH_GROUP_2048_BIT_MODP_DATA_LEN = 256;

    /** Supported dhGroup falls into {@link DhGroup} */
    public final int dhGroup;

    public final byte[] keyExchangeData;

    /**
     * Construct an instance of IkeKePayload in the context of IkePayloadFactory
     *
     * @param critical indicates if this payload is critical. Ignored in supported payload as
     *     instructed by the RFC 7296.
     * @param payloadBody payload body in byte array
     * @throws IkeException if there is any error
     * @see <a href="https://tools.ietf.org/html/rfc7296#page-76">RFC 7296, Internet Key Exchange
     *     Protocol Version 2 (IKEv2), Critical.
     */
    IkeKePayload(boolean critical, byte[] payloadBody) throws IkeException {
        super(PAYLOAD_TYPE_KE, critical);
        ByteBuffer inputBuffer = ByteBuffer.wrap(payloadBody);
        dhGroup = Short.toUnsignedInt(inputBuffer.getShort());
        // Skip reserved field
        inputBuffer.getShort();

        int dataSize = payloadBody.length - KE_HEADER_LEN;
        // Check if dataSize matches the DH group type
        boolean isValidSyntax = true;
        switch (dhGroup) {
            case DH_GROUP_1024_BIT_MODP:
                isValidSyntax = DH_GROUP_1024_BIT_MODP_DATA_LEN == dataSize;
                break;
            case DH_GROUP_2048_BIT_MODP:
                isValidSyntax = DH_GROUP_2048_BIT_MODP_DATA_LEN == dataSize;
                break;
            default:
                // For unsupported DH group, we cannot check its syntax. Upper layer will ingore
                // this payload.
        }
        if (!isValidSyntax) {
            throw new InvalidSyntaxException("Invalid KE payload length for provided DH group.");
        }

        keyExchangeData = new byte[dataSize];
        inputBuffer.get(keyExchangeData);
    }
    // TODO: Add a constructor for generating Dh value and building KE payload.
    // TODO: Add a method for doing DH exchange calculation.
}
