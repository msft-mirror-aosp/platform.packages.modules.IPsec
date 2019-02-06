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

package com.android.ike.ikev2;

import android.annotation.IntDef;
import android.util.ArraySet;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Set;

/**
 * SaProposal represents a user configured set contains cryptograhic algorithms and key generating
 * materials for negotiating an IKE or Child SA.
 *
 * <p>User must provide at least a valid SaProposal when they are creating a new IKE SA or Child SA.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class SaProposal {

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        ENCRYPTION_ALGORITHM_3DES,
        ENCRYPTION_ALGORITHM_AES_CBC,
        ENCRYPTION_ALGORITHM_AES_GCM_8,
        ENCRYPTION_ALGORITHM_AES_GCM_12,
        ENCRYPTION_ALGORITHM_AES_GCM_16
    })
    public @interface EncryptionAlgorithm {}

    public static final int ENCRYPTION_ALGORITHM_3DES = 3;
    public static final int ENCRYPTION_ALGORITHM_AES_CBC = 12;
    public static final int ENCRYPTION_ALGORITHM_AES_GCM_8 = 18;
    public static final int ENCRYPTION_ALGORITHM_AES_GCM_12 = 19;
    public static final int ENCRYPTION_ALGORITHM_AES_GCM_16 = 20;

    private static final Set<Integer> SUPPORTED_ENCRYPTION_ALGORITHM;

    static {
        SUPPORTED_ENCRYPTION_ALGORITHM = new ArraySet<>();
        SUPPORTED_ENCRYPTION_ALGORITHM.add(ENCRYPTION_ALGORITHM_3DES);
        SUPPORTED_ENCRYPTION_ALGORITHM.add(ENCRYPTION_ALGORITHM_AES_CBC);
        SUPPORTED_ENCRYPTION_ALGORITHM.add(ENCRYPTION_ALGORITHM_AES_GCM_8);
        SUPPORTED_ENCRYPTION_ALGORITHM.add(ENCRYPTION_ALGORITHM_AES_GCM_12);
        SUPPORTED_ENCRYPTION_ALGORITHM.add(ENCRYPTION_ALGORITHM_AES_GCM_16);
    }

    public static final int KEY_LEN_AES_128 = 128;
    public static final int KEY_LEN_AES_192 = 192;
    public static final int KEY_LEN_AES_256 = 256;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        PSEUDORANDOM_FUNCTION_HMAC_SHA1,
        PSEUDORANDOM_FUNCTION_AES128_XCBC
    })

    public @interface PseudorandomFunction {}

    public static final int PSEUDORANDOM_FUNCTION_HMAC_SHA1 = 2;
    public static final int PSEUDORANDOM_FUNCTION_AES128_XCBC = 4;

    private static final Set<Integer> SUPPORTED_PSEUDORANDOM_FUNCTION;

    static {
        SUPPORTED_PSEUDORANDOM_FUNCTION = new ArraySet<>();
        SUPPORTED_PSEUDORANDOM_FUNCTION.add(PSEUDORANDOM_FUNCTION_HMAC_SHA1);
        SUPPORTED_PSEUDORANDOM_FUNCTION.add(PSEUDORANDOM_FUNCTION_AES128_XCBC);
    }

    /**
     * Check if the provided algorithm is a supported encryption algorithm.
     *
     * @param algorithm IKE standard encryption algorithm id.
     * @return true if the provided algorithm is a supported encryption algorithm.
     */
    public static boolean isSupportedEncryptionAlgorithm(@EncryptionAlgorithm int algorithm) {
        return SUPPORTED_ENCRYPTION_ALGORITHM.contains(algorithm);
    }

    /**
     * Check if the provided algorithm is a supported pseudorandom function.
     *
     * @param algorithm IKE standard pseudorandom function id.
     * @return true if the provided algorithm is a supported pseudorandom function.
     */
    public static boolean isSupportedPseudorandomFunction(@PseudorandomFunction int algorithm) {
        return SUPPORTED_PSEUDORANDOM_FUNCTION.contains(algorithm);
    }

    // TODO: Implement constructing SaProposal with a Builder that supports adding
    // encryption/integrity algorithms, prf, and DH Group.
}
