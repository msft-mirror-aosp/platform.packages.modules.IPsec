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

import com.android.ike.ikev2.SaProposal;
import com.android.ike.ikev2.message.IkeSaPayload.PrfTransform;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * IkePrf represents a negotiated pseudorandom function.
 *
 * <p>Pseudorandom function is usually used for IKE SA authentication and generating keying
 * materials.
 *
 * <p>For pseudorandom functions based on integrity algorithms, all operations will be done by a
 * {@link Mac}. For pseudorandom functions based on encryption algorithms, all operations will be
 * done by a {@link Cipher}.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public final class IkePrf {
    // STOPSHIP: b/130190639 Catch unchecked exceptions, notify users and close the IKE session.

    @SaProposal.PseudorandomFunction private final int mAlgorithmId;
    private final int mKeyLength;
    private final String mAlgorithmName;

    private final boolean mUseEncryptAlgo;
    private final Mac mMac;
    private final Cipher mCipher;

    /**
     * Construct an instance of IkePrf
     *
     * @param prfTransform the valid negotiated PrfTransform.
     * @param provider the security provider.
     */
    public IkePrf(PrfTransform prfTransform, Provider provider) {
        mAlgorithmId = prfTransform.id;

        switch (mAlgorithmId) {
            case SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1:
                mKeyLength = 20;
                mAlgorithmName = "HmacSHA1";
                mUseEncryptAlgo = false;
                break;
            case SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC:
                mKeyLength = 16;
                mUseEncryptAlgo = true;

                // TODO:Set mAlgorithmName
                throw new UnsupportedOperationException(
                        "Do not support PSEUDORANDOM_FUNCTION_AES128_XCBC.");
            default:
                throw new IllegalArgumentException("Unrecognized PRF ID: " + mAlgorithmId);
        }

        try {
            if (mUseEncryptAlgo) {
                mMac = null;
                mCipher = Cipher.getInstance(mAlgorithmName, provider);
            } else {
                mMac = Mac.getInstance(mAlgorithmName, provider);
                mCipher = null;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Failed to construct IkePrf: ", e);
        }
    }

    /**
     * Get key length of this pseudorandom function (in bytes).
     *
     * @return the key length (in bytes).
     */
    public int getKeyLength() {
        return mKeyLength;
    }

    /**
     * Signs the bytes to generate a Message Authentication Code (MAC).
     *
     * <p>It is usually called for doing IKE authentication or generating keying materials.
     *
     * @param keyBytes the key to sign data.
     * @param dataToSign the data to be signed.
     * @return the calculated MAC.
     */
    public byte[] signBytes(byte[] keyBytes, byte[] dataToSign) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, mAlgorithmName);

            if (mUseEncryptAlgo) {
                throw new UnsupportedOperationException(
                        "Do not support PRF using encryption algorithm.");

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
     * Generates SKEYSEED based on the nonces and shared DH secret.
     *
     * @param nonceInit the IKE initiator nonce.
     * @param nonceResp the IKE responder nonce.
     * @param sharedDhKey the DH shared key.
     * @return the byte array of SKEYSEED.
     */
    public byte[] generateSKeySeed(byte[] nonceInit, byte[] nonceResp, byte[] sharedDhKey) {
        // TODO: If it is PSEUDORANDOM_FUNCTION_AES128_XCBC, only use first 8 bytes of each nonce.

        ByteBuffer keyBuffer = ByteBuffer.allocate(nonceInit.length + nonceResp.length);
        keyBuffer.put(nonceInit).put(nonceResp);

        return signBytes(keyBuffer.array(), sharedDhKey);
    }

    /**
     * Derives keying materials from IKE/Child SA negotiation.
     *
     * <p>prf+(K, S) outputs a pseudorandom stream by using negotiated PRF iteratively. In this way
     * it can generate long enough keying material containing all the keys for this IKE/Child SA.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7296#section-2.13">RFC 7296 Internet Key
     *     Exchange Protocol Version 2 (IKEv2) 2.13. Generating Keying Material </a>
     * @param keyBytes the key to sign data.
     * @param dataToSign the data to be signed.
     * @param keyMaterialLen the length of keying materials.
     * @return the byte array of keying materials
     */
    public byte[] generateKeyMat(byte[] keyBytes, byte[] dataToSign, int keyMaterialLen) {
        ByteBuffer keyMatBuffer = ByteBuffer.allocate(keyMaterialLen);

        byte[] previousMac = new byte[0];
        final int padLen = 1;
        byte padValue = 1;

        while (keyMatBuffer.remaining() > 0) {
            ByteBuffer dataToSignBuffer =
                    ByteBuffer.allocate(previousMac.length + dataToSign.length + padLen);
            dataToSignBuffer.put(previousMac).put(dataToSign).put(padValue);

            previousMac = signBytes(keyBytes, dataToSignBuffer.array());

            keyMatBuffer.put(
                    previousMac, 0, Math.min(previousMac.length, keyMatBuffer.remaining()));

            padValue++;
        }

        return keyMatBuffer.array();
    }
}
