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
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 * IkeMacPrf represents a negotiated pseudorandom function.
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
public final class IkeMacPrf extends IkeMac {
    // STOPSHIP: b/130190639 Catch unchecked exceptions, notify users and close the IKE session.

    private IkeMacPrf(
            @SaProposal.PseudorandomFunction int algorithmId,
            int keyLength,
            String algorithmName,
            boolean isEncryptAlgo,
            Provider provider) {
        super(algorithmId, keyLength, algorithmName, isEncryptAlgo, provider);
    }

    /**
     * Construct an instance of IkeMacPrf.
     *
     * @param prfTransform the valid negotiated PrfTransform.
     * @param provider the security provider.
     * @return an instance of IkeMacPrf.
     */
    public static IkeMacPrf create(PrfTransform prfTransform, Provider provider) {
        int algorithmId = prfTransform.id;

        int keyLength = 0;
        String algorithmName = "";
        boolean isEncryptAlgo = false;

        switch (algorithmId) {
            case SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1:
                keyLength = 20;
                algorithmName = "HmacSHA1";
                break;
            case SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC:
                keyLength = 16;
                isEncryptAlgo = true;

                // TODO:Set mAlgorithmName
                throw new UnsupportedOperationException(
                        "Do not support PSEUDORANDOM_FUNCTION_AES128_XCBC.");
            default:
                throw new IllegalArgumentException("Unrecognized PRF ID: " + algorithmId);
        }

        return new IkeMacPrf(algorithmId, keyLength, algorithmName, isEncryptAlgo, provider);
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
     * @param keyBytes the key to sign data. SKEYSEED is used for generating KEYMAT for IKE SA. SK_d
     *     is used for generating KEYMAT for Child SA.
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

    /**
     * Returns algorithm type as a String.
     *
     * @return the algorithm type as a String.
     */
    @Override
    public String getTypeString() {
        return "Pseudorandom Function";
    }
}
