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

package com.android.internal.net.ipsec.ike.crypto;

import android.net.IpSecAlgorithm;
import android.net.ipsec.ike.SaProposal;

import com.android.internal.net.ipsec.ike.message.IkeSaPayload.EncryptionTransform;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * IkeCipher contains common information of normal and combined mode encryption algorithms.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public abstract class IkeCipher extends IkeCrypto {
    private static final int KEY_LEN_3DES = 24;
    private static final int KEY_LEN_CHACHA20_POLY1305 = 32;

    private static final int IV_LEN_3DES = 8;
    private static final int IV_LEN_AES_CBC = 16;
    private static final int IV_LEN_AES_CTR = 8;
    private static final int IV_LEN_AES_GCM = 8;
    private static final int IV_LEN_CHACHA20_POLY1305 = 8;

    private static final int SALT_LEN_AES_GCM = 4;
    private static final int SALT_LEN_AES_CTR = 4;
    private static final int SALT_LEN_AES_CHACHA20_POLY1305 = 4;

    private static final int BLOCK_SIZE_CHACHA_POLY = 4;

    protected static final int SALT_LEN_NOT_INCLUDED = 0;
    protected static final int BLOCK_SIZE_NOT_SPECIFIED = 0;

    private final boolean mIsAead;
    private final int mIvLen;
    private final int mBlockSize;

    protected final int mSaltLen;
    protected final Cipher mCipher;

    protected IkeCipher(
            int algorithmId,
            int keyLength,
            int ivLength,
            String algorithmName,
            boolean isAead,
            int saltLen,
            int blockSize) {
        super(algorithmId, keyLength, algorithmName);
        mIvLen = ivLength;
        mIsAead = isAead;
        mSaltLen = saltLen;

        try {
            mCipher = Cipher.getInstance(getAlgorithmName());
            mBlockSize = blockSize == BLOCK_SIZE_NOT_SPECIFIED ? mCipher.getBlockSize() : blockSize;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Failed to construct " + getTypeString(), e);
        }
    }

    /**
     * Contruct an instance of IkeCipher.
     *
     * @param encryptionTransform the valid negotiated EncryptionTransform.
     * @return an instance of IkeCipher.
     */
    public static IkeCipher create(EncryptionTransform encryptionTransform) {
        int algorithmId = encryptionTransform.id;

        // Use specifiedKeyLength for algorithms with variable key length. Since
        // specifiedKeyLength are encoded in bits, it needs to be converted to bytes.
        switch (algorithmId) {
            case SaProposal.ENCRYPTION_ALGORITHM_3DES:
                return new IkeNormalModeCipher(
                        algorithmId, KEY_LEN_3DES, IV_LEN_3DES, "DESede/CBC/NoPadding");
            case SaProposal.ENCRYPTION_ALGORITHM_AES_CBC:
                return new IkeNormalModeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        IV_LEN_AES_CBC,
                        "AES/CBC/NoPadding");
            case SaProposal.ENCRYPTION_ALGORITHM_AES_CTR:
                return new IkeNormalModeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        IV_LEN_AES_CTR,
                        "AES/CTR/NoPadding",
                        SALT_LEN_AES_CTR);
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8:
                // Fall through
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12:
                // Fall through
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16:
                // Fall through
                return new IkeCombinedModeCipher(
                        algorithmId,
                        encryptionTransform.getSpecifiedKeyLength() / 8,
                        IV_LEN_AES_GCM,
                        "AES/GCM/NoPadding",
                        SALT_LEN_AES_GCM);
            case SaProposal.ENCRYPTION_ALGORITHM_CHACHA20_POLY1305:
                return new IkeCombinedModeCipher(
                        algorithmId,
                        KEY_LEN_CHACHA20_POLY1305,
                        IV_LEN_CHACHA20_POLY1305,
                        "ChaCha20/Poly1305/NoPadding",
                        SALT_LEN_AES_CHACHA20_POLY1305,
                        BLOCK_SIZE_CHACHA_POLY);
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
        return mBlockSize;
    }

    /**
     * Get initialization vector (IV) length.
     *
     * @return the IV length.
     */
    public int getIvLen() {
        return mIvLen;
    }

    /**
     * Generate initialization vector (IV).
     *
     * @return the initialization vector (IV).
     */
    public byte[] generateIv() {
        byte[] iv = new byte[getIvLen()];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    protected void validateKeyLenOrThrow(byte[] key) {
        if (key.length != getKeyLength()) {
            throw new IllegalArgumentException(
                    "Expected key with length of : "
                            + getKeyLength()
                            + " Received key with length of : "
                            + key.length);
        }
    }

    @Override
    public int getKeyLength() {
        return super.getKeyLength() + mSaltLen;
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
    public abstract IpSecAlgorithm buildIpSecAlgorithmWithKey(byte[] key);

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
