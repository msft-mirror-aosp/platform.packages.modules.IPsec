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

import java.security.Provider;

/**
 * IkeCipher represents a negotiated combined-mode cipher(AEAD) encryption algorithm.
 *
 * <p>Checksum mentioned in this class is also known as authentication tag or Integrity Checksum
 * Vector(ICV)
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3.2">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 * @see <a href="https://tools.ietf.org/html/rfc5282">RFC 5282,Using Authenticated Encryption
 *     Algorithms with the Encrypted Payload of the Internet Key Exchange version 2 (IKEv2)
 *     Protocol</a>
 */
public final class IkeCombinedModeCipher extends IkeCipher {
    private final int mChecksumLen;

    /** Package private */
    IkeCombinedModeCipher(
            int algorithmId, int keyLength, int ivLength, String algorithmName, Provider provider) {
        super(algorithmId, keyLength, ivLength, algorithmName, true /*isAead*/, provider);
        switch (algorithmId) {
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8:
                mChecksumLen = 8;
                break;
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12:
                mChecksumLen = 12;
                break;
            case SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16:
                mChecksumLen = 16;
                break;
            default:
                throw new IllegalArgumentException(
                        "Unrecognized Encryption Algorithm ID: " + algorithmId);
        }
    }

    /**
     * Returns length of checksum.
     *
     * @return the length of checksum in bytes.
     */
    public int getChecksumLen() {
        return mChecksumLen;
    }

    @Override
    public IpSecAlgorithm buildIpSecAlgorithmWithKey(byte[] key) {
        validateKeyLenOrThrow(key);
        return new IpSecAlgorithm(IpSecAlgorithm.AUTH_CRYPT_AES_GCM, key, mChecksumLen * 8);
    }

    // TODO: Support encryption and decryption.
}
