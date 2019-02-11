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

import java.nio.ByteBuffer;

/**
 * IkeAuthPskPayload represents an Authentication Payload using Pre-Shared Key to do authentication.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.8">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeAuthPskPayload extends IkeAuthPayload {
    public final byte[] signature;

    protected IkeAuthPskPayload(boolean critical, byte[] authData) throws IkeException {
        super(critical, IkeAuthPayload.AUTH_METHOD_PRE_SHARED_KEY);
        signature = authData;
    }

    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        // TODO: Implement it.
        throw new UnsupportedOperationException(
                "It is not supported to encode a " + getTypeString());
    }

    @Override
    protected int getPayloadLength() {
        // TODO: Implement it.
        throw new UnsupportedOperationException(
                "It is not supported to get payload length of " + getTypeString());
    }

    @Override
    public String getTypeString() {
        return "Authentication-PSK Payload";
    }
}
