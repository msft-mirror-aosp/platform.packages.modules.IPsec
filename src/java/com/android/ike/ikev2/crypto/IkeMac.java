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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * IkeMac is an abstract class that represents common information for all negotiated algorithms that
 * generates Message Authentication Code (MAC), e.g. PRF and integrity algorithm.
 */
abstract class IkeMac {
    // STOPSHIP: b/130190639 Catch unchecked exceptions, notify users and close the IKE session.
    private final int mAlgorithmId;
    private final int mKeyLength;
    private final String mAlgorithmName;

    private final boolean mIsEncryptAlgo;
    private final Mac mMac;
    private final Cipher mCipher;

    protected IkeMac(
            int algorithmId,
            int keyLength,
            String algorithmName,
            boolean isEncryptAlgo,
            Provider provider) {
        mAlgorithmId = algorithmId;
        mKeyLength = keyLength;
        mAlgorithmName = algorithmName;
        mIsEncryptAlgo = isEncryptAlgo;

        try {
            if (mIsEncryptAlgo) {
                mMac = null;
                mCipher = Cipher.getInstance(mAlgorithmName, provider);
            } else {
                mMac = Mac.getInstance(mAlgorithmName, provider);
                mCipher = null;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Failed to construct " + getTypeString(), e);
        }
    }

    /**
     * Gets key length of this integrity algorithm (in bytes).
     *
     * @return the key length (in bytes).
     */
    public int getKeyLength() {
        return mKeyLength;
    }

    /**
     * Signs the bytes to generate a Message Authentication Code (MAC).
     *
     * <p>Caller is responsible for providing valid key according to their use cases (e.g. PSK,
     * SK_p, SK_d ...).
     *
     * @param keyBytes the key to sign data.
     * @param dataToSign the data to be signed.
     * @return the calculated MAC.
     */
    public byte[] signBytes(byte[] keyBytes, byte[] dataToSign) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, mAlgorithmName);

            if (mIsEncryptAlgo) {
                throw new UnsupportedOperationException(
                        "Do not support " + getTypeString() + " using encryption algorithm.");
            } else {
                ByteBuffer inputBuffer = ByteBuffer.wrap(dataToSign);
                mMac.init(secretKey);
                mMac.update(inputBuffer);

                return mMac.doFinal();
            }
        } catch (InvalidKeyException | IllegalStateException e) {
            throw new IllegalArgumentException("Failed to generate MAC: ", e);
        }
    }

    /**
     * Returns algorithm type as a String.
     *
     * @return the algorithm type as a String.
     */
    public abstract String getTypeString();
}
