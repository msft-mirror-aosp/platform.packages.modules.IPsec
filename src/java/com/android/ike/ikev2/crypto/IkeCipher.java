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

package com.android.ike.ikev2.crypto;

import android.net.IpSecAlgorithm;

import com.android.ike.ikev2.SaProposal;
import com.android.ike.ikev2.message.IkeSaPayload.EncryptionTransform;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * IkeCipher represents a negotiated encryption algorithm.
 *
 * <p>IkeCipher is either a combined-mode cipher(AEAD) or a normal-mode cipher. Users should call
 * the right decryption and encryption methods according to the IkeCipher mode.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public final class IkeCipher extends IkeCrypto {
    // Authentication tag is only used in an AEAD.
    private static final int AUTH_TAG_LEN_UNUSED = 0;

    private final boolean mIsAead;
    private final int mAuthTagLen;
    private final Cipher mCipher;

    private IkeCipher(
            int algorithmId,
            int keyLength,
            String algorithmName,
            boolean isAead,
            int authTagLen,
            Provider provider) {
        super(algorithmId, keyLength, algorithmName);
        mIsAead = isAead;
        mAuthTagLen = authTagLen;

        try {
            mCipher = Cipher.getInstance(getAlgorithmName(), provider);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Failed to construct " + getTypeString(), e);
        }
    }

    /**
     * Contruct an instance of IkeCipher.
     *
     * @param encryptionTransform the valid negotiated EncryptionTransform.
     * @param provider the security provider.
     * @return an instance of IkeCipher.
     */
    public static IkeCipher create(EncryptionTransform encryptionTransform, Provider provider) {
        int algorithmId = encryptionTransform.id;

        // Use specifiedKeyLength for algorithms with variable key length. Since
        // specifiedKeyLength are encoded in bits, it needs to be converted to bytes.
        switch (algorithmId) {
            case SaProposal.ENCRYPTION_ALGORITHM_3DES:
                return new IkeCipher(
                        algorithmId,
                        20 /*keyLength*/,
                        "DESede/CBC/NoPadding",
                        false /*isAead*/,
                        AUTH_TAG_LEN_UNUSED,
                        provider);
            case SaProposal.ENCRYPTION_ALGORITHM_AES_CBC:
                return new IkeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        "AES/CBC/NoPadding",
                        false /*isAead*/,
                        AUTH_TAG_LEN_UNUSED,
                        provider);
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8:
                return new IkeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        "AES/GCM/NoPadding",
                        true /*isAead*/,
                        8 /*authTagLen*/,
                        provider);
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12:
                return new IkeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        "AES/GCM/NoPadding",
                        true /*isAead*/,
                        12 /*authTagLen*/,
                        provider);
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16:
                return new IkeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        "AES/GCM/NoPadding",
                        true /*isAead*/,
                        16 /*authTagLen*/,
                        provider);
            default:
                throw new IllegalArgumentException(
                        "Unrecognized Encryption Algorithm ID: " + algorithmId);
        }
    }

    /**
     * Check if this encryption algorithm is a combined-mode/AEAD algorithm.
     *
     * @return if this encryption algorithm is a combined-mode/AEAD algorithm.
     */
    public boolean isAead() {
        return mIsAead;
    }

    /**
     * Get the block size (in bytes).
     *
     * @return the block size (in bytes).
     */
    public int getBlockSize() {
        // Currently all supported encryption algorithms are block ciphers. So the return value will
        // not be zero.
        return mCipher.getBlockSize();
    }

    /**
     * Generate initialization vector (IV).
     *
     * @return the initialization vector (IV).
     */
    public byte[] generateIv() {
        byte[] iv = new byte[getBlockSize()];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] doCipherAction(byte[] data, byte[] keyBytes, byte[] ivBytes, int opmode)
            throws IllegalBlockSizeException {
        if (mIsAead) {
            throw new IllegalArgumentException("This method cannot be applied to AEAD.");
        }
        if (getKeyLength() != keyBytes.length) {
            throw new IllegalArgumentException(
                    "Expected key length: "
                            + getKeyLength()
                            + " Received key length: "
                            + keyBytes.length);
        }
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, getAlgorithmName());
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            mCipher.init(opmode, key, iv);

            ByteBuffer inputBuffer = ByteBuffer.wrap(data);
            ByteBuffer outputBuffer = ByteBuffer.allocate(data.length);

            mCipher.doFinal(inputBuffer, outputBuffer);
            return outputBuffer.array();
        } catch (InvalidKeyException
                | InvalidAlgorithmParameterException
                | BadPaddingException
                | ShortBufferException e) {
            String errorMessage =
                    Cipher.ENCRYPT_MODE == opmode
                            ? "Failed to encrypt data: "
                            : "Failed to decrypt data: ";
            throw new IllegalArgumentException(errorMessage, e);
        }
    }

    /**
     * Encrypt padded data using normal-mode cipher.
     *
     * @param paddedData the padded data to encrypt.
     * @param keyBytes the encryption key.
     * @param ivBytes the initialization vector (IV).
     * @return the encrypted and padded data.
     */
    public byte[] encrypt(byte[] paddedData, byte[] keyBytes, byte[] ivBytes) {
        try {
            return doCipherAction(paddedData, keyBytes, ivBytes, Cipher.ENCRYPT_MODE);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalArgumentException("Failed to encrypt data: ", e);
        }
    }

    /**
     * Decrypt the encrypted and padded data.
     *
     * @param encryptedData the encrypted and padded data.
     * @param keyBytes the decryption key.
     * @param ivBytes the initialization vector (IV).
     * @return the decrypted and padded data.
     * @throws IllegalBlockSizeException if the total encryptedData length is not a multiple of
     *     block size.
     */
    public byte[] decrypt(byte[] encryptedData, byte[] keyBytes, byte[] ivBytes)
            throws IllegalBlockSizeException {
        return doCipherAction(encryptedData, keyBytes, ivBytes, Cipher.DECRYPT_MODE);
    }

    /**
     * Build IpSecAlgorithm from this IkeCipher.
     *
     * <p>Build IpSecAlgorithm that represents the same encryption algorithm with this IkeCipher
     * instance with provided encryption key.
     *
     * @param key the encryption key in byte array.
     * @return the IpSecAlgorithm.
     */
    public IpSecAlgorithm buildIpSecAlgorithmWithKey(byte[] key) {
        if (key.length != getKeyLength()) {
            throw new IllegalArgumentException(
                    "Expected key with length of : "
                            + getKeyLength()
                            + " Received key with length of : "
                            + key.length);
        }

        switch (getAlgorithmId()) {
            case SaProposal.ENCRYPTION_ALGORITHM_3DES:
                // TODO: Consider supporting 3DES in IpSecTransform.
                throw new UnsupportedOperationException("Do not support 3Des encryption.");
            case SaProposal.ENCRYPTION_ALGORITHM_AES_CBC:
                return new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, key);
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8:
                // Fall through;
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12:
                // Fall through;
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16:
                return new IpSecAlgorithm(IpSecAlgorithm.AUTH_CRYPT_AES_GCM, key, mAuthTagLen * 8);
            default:
                throw new IllegalArgumentException(
                        "Unrecognized Encryption Algorithm ID: " + getAlgorithmId());
        }
    }

    // TODO: Support encryption and decryption of AEAD.

    /**
     * Returns algorithm type as a String.
     *
     * @return the algorithm type as a String.
     */
    @Override
    public String getTypeString() {
        return "Encryption Algorithm";
    }
}
