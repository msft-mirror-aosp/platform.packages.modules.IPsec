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

package com.android.ike.ikev2.message;

import com.android.ike.ikev2.exceptions.IkeException;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * IkeEncryptedPayloadBody is a package private class that represents an IKE payload substructure
 * that contains initialization vector, encrypted content, padding, pad length and integrity
 * checksum.
 *
 * <p>Both an Encrypted Payload (IkeSkPayload) and an EncryptedFragmentPayload (IkeSkfPayload)
 * consists of an IkeEncryptedPayloadBody instance.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#page-105">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 * @see <a href="https://tools.ietf.org/html/rfc7383#page-6">RFC 7383, Internet Key Exchange
 *     Protocol Version 2 (IKEv2) Message Fragmentation
 */
final class IkeEncryptedPayloadBody {
    // Length of pad length field.
    private static final int PAD_LEN_LEN = 1;

    private final byte[] mUnencryptedData;
    private final byte[] mEncryptedAndPaddedData;
    private final byte[] mIv;
    private final byte[] mIntegrityChecksum;

    /**
     * Package private constructor for constructing an instance of IkeEncryptedPayloadBody from
     * decrypting an incoming packet.
     */
    IkeEncryptedPayloadBody(
            byte[] message,
            Mac integrityMac,
            int expectedChecksumLen,
            Cipher decryptCipher,
            SecretKey dKey)
            throws IkeException, GeneralSecurityException {
        ByteBuffer inputBuffer = ByteBuffer.wrap(message);

        // Skip IKE header and SK payload header
        byte[] tempArray = new byte[IkeHeader.IKE_HEADER_LENGTH + IkePayload.GENERIC_HEADER_LENGTH];
        inputBuffer.get(tempArray);

        // Extract bytes for authentication and decryption.
        int expectedIvLen = decryptCipher.getBlockSize();
        mIv = new byte[expectedIvLen];

        int encryptedDataLen =
                message.length
                        - (IkeHeader.IKE_HEADER_LENGTH
                                + IkePayload.GENERIC_HEADER_LENGTH
                                + expectedIvLen
                                + expectedChecksumLen);
        // IkeMessage will catch exception if encryptedDataLen is negative.
        mEncryptedAndPaddedData = new byte[encryptedDataLen];

        mIntegrityChecksum = new byte[expectedChecksumLen];
        inputBuffer.get(mIv).get(mEncryptedAndPaddedData).get(mIntegrityChecksum);

        // Authenticate and decrypt.
        validateChecksumOrThrow(message, integrityMac, expectedChecksumLen, mIntegrityChecksum);
        mUnencryptedData = decrypt(mEncryptedAndPaddedData, decryptCipher, dKey, mIv);
    }

    // TODO: Add another constructor for AEAD protected payload.

    // TODO: Add constructors that initiate IkeEncryptedPayloadBody for an outbound packet

    private static void validateChecksumOrThrow(
            byte[] message, Mac integrityMac, int expectedChecksumLen, byte[] integrityChecksum)
            throws GeneralSecurityException {
        ByteBuffer inputBuffer = ByteBuffer.wrap(message, 0, message.length - expectedChecksumLen);
        integrityMac.update(inputBuffer);
        byte[] calculatedChecksum =
                Arrays.copyOfRange(integrityMac.doFinal(), 0, expectedChecksumLen);

        if (!Arrays.equals(integrityChecksum, calculatedChecksum)) {
            throw new GeneralSecurityException("Message authentication failed.");
        }
    }

    private static byte[] decrypt(
            byte[] encryptedData, Cipher decryptCipher, SecretKey dKey, byte[] iv)
            throws GeneralSecurityException {
        decryptCipher.init(Cipher.DECRYPT_MODE, dKey, new IvParameterSpec(iv));

        ByteBuffer inputBuffer = ByteBuffer.wrap(encryptedData);
        ByteBuffer outputBuffer = ByteBuffer.allocate(encryptedData.length);
        decryptCipher.doFinal(inputBuffer, outputBuffer);

        // Remove padding
        outputBuffer.rewind();
        int padLength = Byte.toUnsignedInt(outputBuffer.get(encryptedData.length - PAD_LEN_LEN));
        byte[] decryptedData = new byte[encryptedData.length - padLength - PAD_LEN_LEN];

        outputBuffer.get(decryptedData);
        return decryptedData;
    }

    /** Package private */
    byte[] getUnencryptedData() {
        return mUnencryptedData;
    }

    /** Package private */
    int getLength() {
        return (mIv.length + mEncryptedAndPaddedData.length + mIntegrityChecksum.length);
    }

    /** Package private */
    byte[] encode() {
        ByteBuffer buffer = ByteBuffer.allocate(getLength());
        buffer.put(mIv).put(mEncryptedAndPaddedData).put(mIntegrityChecksum);
        return buffer.array();
    }
}
