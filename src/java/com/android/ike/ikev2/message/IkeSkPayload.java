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

import com.android.ike.ikev2.message.IkePayload.PayloadType;

import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * IkeSkPayload represents a Encrypted Payload.
 *
 * <p>It contains other payloads in encrypted form. It is must be the last payload in the message.
 * It should be the only payload in this implementation.
 *
 * <p>Critical bit must be ignored when doing decoding.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#page-105">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeSkPayload extends IkePayload {

    public final byte[] unencryptedPayloads;

    /**
     * Construct an instance of IkeSkPayload in the context of {@link IkePayloadFactory}.
     *
     * @param critical indicates if it is a critical payload.
     * @param message the byte array contains the whole IKE message.
     * @param integrityMac the initialized Mac for integrity check.
     * @param checksumLen the length of integrity checksum.
     * @param decryptCipher the uninitialized Cipher for doing decryption.
     * @param dKey the decryption key.
     * @param ivLen the length of Initialization Vector.
     */
    IkeSkPayload(
            boolean critical,
            byte[] message,
            Mac integrityMac,
            int checksumLen,
            Cipher decryptCipher,
            SecretKey dKey,
            int ivLen) {
        super(PAYLOAD_TYPE_SK, critical);
        // TODO:Check integrity and decrypt SkPayload body.
        throw new UnsupportedOperationException("It is not supported to construct a SkPayload.");
    }

    //TODO: Add another constructor for AEAD protected payload.

    /**
     * Throw an Exception when trying to encode this payload.
     *
     * @throws UnsupportedOperationException for this payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        // TODO: Implement thie method
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
        // TODO: Implement thie method
        throw new UnsupportedOperationException(
                "It is not supported to get length of  a " + getTypeString());
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        return "Encrypted and Authenticated Payload";
    }
}
