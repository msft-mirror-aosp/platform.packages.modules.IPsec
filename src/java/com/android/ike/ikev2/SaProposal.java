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

import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload.DhGroupTransform;
import com.android.ike.ikev2.message.IkeSaPayload.EncryptionTransform;
import com.android.ike.ikev2.message.IkeSaPayload.IntegrityTransform;
import com.android.ike.ikev2.message.IkeSaPayload.PrfTransform;

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
    @IntDef({PSEUDORANDOM_FUNCTION_HMAC_SHA1, PSEUDORANDOM_FUNCTION_AES128_XCBC})
    public @interface PseudorandomFunction {}

    public static final int PSEUDORANDOM_FUNCTION_HMAC_SHA1 = 2;
    public static final int PSEUDORANDOM_FUNCTION_AES128_XCBC = 4;

    private static final Set<Integer> SUPPORTED_PSEUDORANDOM_FUNCTION;

    static {
        SUPPORTED_PSEUDORANDOM_FUNCTION = new ArraySet<>();
        SUPPORTED_PSEUDORANDOM_FUNCTION.add(PSEUDORANDOM_FUNCTION_HMAC_SHA1);
        SUPPORTED_PSEUDORANDOM_FUNCTION.add(PSEUDORANDOM_FUNCTION_AES128_XCBC);
    }

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        INTEGRITY_ALGORITHM_NONE,
        INTEGRITY_ALGORITHM_HMAC_SHA1_96,
        INTEGRITY_ALGORITHM_AES_XCBC_96,
        INTEGRITY_ALGORITHM_HMAC_SHA2_256_128,
        INTEGRITY_ALGORITHM_HMAC_SHA2_384_192,
        INTEGRITY_ALGORITHM_HMAC_SHA2_512_256
    })
    public @interface IntegrityAlgorithm {}

    public static final int INTEGRITY_ALGORITHM_NONE = 0;
    public static final int INTEGRITY_ALGORITHM_HMAC_SHA1_96 = 2;
    public static final int INTEGRITY_ALGORITHM_AES_XCBC_96 = 5;
    public static final int INTEGRITY_ALGORITHM_HMAC_SHA2_256_128 = 12;
    public static final int INTEGRITY_ALGORITHM_HMAC_SHA2_384_192 = 13;
    public static final int INTEGRITY_ALGORITHM_HMAC_SHA2_512_256 = 14;

    private static final Set<Integer> SUPPORTED_INTEGRITY_ALGORITHM;

    static {
        SUPPORTED_INTEGRITY_ALGORITHM = new ArraySet<>();
        SUPPORTED_INTEGRITY_ALGORITHM.add(INTEGRITY_ALGORITHM_NONE);
        SUPPORTED_INTEGRITY_ALGORITHM.add(INTEGRITY_ALGORITHM_HMAC_SHA1_96);
        SUPPORTED_INTEGRITY_ALGORITHM.add(INTEGRITY_ALGORITHM_AES_XCBC_96);
        SUPPORTED_INTEGRITY_ALGORITHM.add(INTEGRITY_ALGORITHM_HMAC_SHA2_256_128);
        SUPPORTED_INTEGRITY_ALGORITHM.add(INTEGRITY_ALGORITHM_HMAC_SHA2_384_192);
        SUPPORTED_INTEGRITY_ALGORITHM.add(INTEGRITY_ALGORITHM_HMAC_SHA2_512_256);
    }

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({DH_GROUP_NONE, DH_GROUP_1024_BIT_MODP, DH_GROUP_2048_BIT_MODP})
    public @interface DhGroup {}

    public static final int DH_GROUP_NONE = 0;
    public static final int DH_GROUP_1024_BIT_MODP = 2;
    public static final int DH_GROUP_2048_BIT_MODP = 14;

    private static final Set<Integer> SUPPORTED_DH_GROUP;

    static {
        SUPPORTED_DH_GROUP = new ArraySet<>();
        SUPPORTED_DH_GROUP.add(DH_GROUP_NONE);
        SUPPORTED_DH_GROUP.add(DH_GROUP_1024_BIT_MODP);
        SUPPORTED_DH_GROUP.add(DH_GROUP_2048_BIT_MODP);
    }

    /** Package private */
    @IkePayload.ProtocolId final int mProtocolId;
    /** Package private */
    final EncryptionTransform[] mEncryptionAlgorithms;
    /** Package private */
    final PrfTransform[] mPseudorandomFunctions;
    /** Package private */
    final IntegrityTransform[] mIntegrityAlgorithms;
    /** Package private */
    final DhGroupTransform[] mDhGroups;

    private SaProposal(
            @IkePayload.ProtocolId int protocol,
            EncryptionTransform[] encryptionAlgos,
            PrfTransform[] prfs,
            IntegrityTransform[] integrityAlgos,
            DhGroupTransform[] dhGroups) {
        mProtocolId = protocol;
        mEncryptionAlgorithms = encryptionAlgos;
        mPseudorandomFunctions = prfs;
        mIntegrityAlgorithms = integrityAlgos;
        mDhGroups = dhGroups;
    }

    /**
     * This class can be used to incrementally construct a SaProposal. SaProposal instances are
     * immutable once built.
     */
    public static final class Builder {
        private static final String ERROR_TAG = "Invalid SA Proposal: ";

        /** Indicate if Builder is for building IKE SA proposal or Child SA proposal. */
        private final boolean mIsIkeProposal;
        /**
         * Indicate if Builder is for building first Child SA proposal or addtional Child SA
         * proposal. Only valid if mIsIkeProposal is false.
         */
        private final boolean mIsFirstChild;

        // Use set to avoid adding repeated algorithms.
        private final Set<EncryptionTransform> mProposedEncryptAlgos = new ArraySet<>();
        private final Set<PrfTransform> mProposedPrfs = new ArraySet<>();
        private final Set<IntegrityTransform> mProposedIntegrityAlgos = new ArraySet<>();
        private final Set<DhGroupTransform> mProposedDhGroups = new ArraySet<>();

        private boolean mHasAead = false;

        private Builder(boolean isIke, boolean isFirstChild) {
            mIsIkeProposal = isIke;
            mIsFirstChild = isFirstChild;
        }

        private static boolean isAead(@EncryptionAlgorithm int algorithm) {
            switch (algorithm) {
                case ENCRYPTION_ALGORITHM_3DES:
                    // Fall through
                case ENCRYPTION_ALGORITHM_AES_CBC:
                    return false;
                case ENCRYPTION_ALGORITHM_AES_GCM_8:
                    // Fall through
                case ENCRYPTION_ALGORITHM_AES_GCM_12:
                    // Fall through
                case ENCRYPTION_ALGORITHM_AES_GCM_16:
                    return true;
                default:
                    // Won't hit here.
                    throw new IllegalArgumentException("Unsupported Encryption Algorithm.");
            }
        }

        private EncryptionTransform[] buildEncryptAlgosOrThrow() {
            if (mProposedEncryptAlgos.isEmpty()) {
                throw new IllegalArgumentException(
                        ERROR_TAG + "Encryption algorithm must be proposed.");
            }

            return (EncryptionTransform[]) mProposedEncryptAlgos.toArray();
        }

        private PrfTransform[] buildPrfsOrThrow() {
            // TODO: Validate that PRF must be proposed for IKE SA and PRF must not be
            // proposed for Child SA.
            throw new UnsupportedOperationException("Cannot validate user proposed algorithm.");
        }

        private IntegrityTransform[] buildIntegAlgosOrThrow() {
            // TODO: Validate proposed integrity algorithms according to existence of AEAD.
            throw new UnsupportedOperationException("Cannot validate user proposed algorithm.");
        }

        private DhGroupTransform[] buildDhGroupsOrThrow() {
            // TODO: Validate proposed DH groups according to the usage of SaProposal (for
            // IKE SA, for first Child SA or for addtional Child SA)
            throw new UnsupportedOperationException("Cannot validate user proposed algorithm.");
        }

        /** Returns a new Builder for a IKE SA Proposal. */
        public static Builder newIkeSaProposalBuilder() {
            return new Builder(true, false);
        }

        /**
         * Returns a new Builder for a Child SA Proposal.
         *
         * @param isFirstChildSaProposal indicates if this SA proposal for first Child SA.
         * @return Builder for a Child SA Proposal.
         */
        public static Builder newChildSaProposalBuilder(boolean isFirstChildSaProposal) {
            return new Builder(false, isFirstChildSaProposal);
        }

        /**
         * Adds an encryption algorithm to SA proposal being built.
         *
         * @param algorithm encryption algorithm to add to SaProposal.
         * @return Builder of SaProposal.
         */
        public Builder addEncryptionAlgorithm(@EncryptionAlgorithm int algorithm) {
            // Construct EncryptionTransform and validate proposed algorithm during
            // construction.
            EncryptionTransform encryptionTransform = new EncryptionTransform(algorithm);

            validateOnlyOneModeEncryptAlgoProposedOrThrow(algorithm);

            mProposedEncryptAlgos.add(encryptionTransform);
            return this;
        }

        /**
         * Adds an encryption algorithm with specific key length to SA proposal being built.
         *
         * @param algorithm encryption algorithm to add to SaProposal.
         * @param keyLength key length of algorithm.
         * @return Builder of SaProposal.
         * @throws IllegalArgumentException if AEAD and non-combined mode algorithms are mixed.
         */
        public Builder addEncryptionAlgorithm(@EncryptionAlgorithm int algorithm, int keyLength) {
            // Construct EncryptionTransform and validate proposed algorithm during
            // construction.
            EncryptionTransform encryptionTransform = new EncryptionTransform(algorithm, keyLength);

            validateOnlyOneModeEncryptAlgoProposedOrThrow(algorithm);

            mProposedEncryptAlgos.add(encryptionTransform);
            return this;
        }

        private void validateOnlyOneModeEncryptAlgoProposedOrThrow(
                @EncryptionAlgorithm int algorithm) {
            boolean isCurrentAead = isAead(algorithm);

            if (!mProposedEncryptAlgos.isEmpty() && (mHasAead ^ isCurrentAead)) {
                throw new IllegalArgumentException(
                        ERROR_TAG
                                + "Proposal cannot has both normal ciphers "
                                + "and combined-mode ciphers.");
            }

            if (isCurrentAead) mHasAead = true;
        }

        /**
         * Adds a pseudorandom function to SA proposal being built.
         *
         * @param algorithm pseudorandom function to add to SaProposal.
         * @return Builder of SaProposal.
         */
        public Builder addPseudorandomFunction(@PseudorandomFunction int algorithm) {
            // Construct PrfTransform and validate proposed algorithm during
            // construction.
            mProposedPrfs.add(new PrfTransform(algorithm));
            return this;
        }

        /**
         * Adds an integrity algorithm to SA proposal being built.
         *
         * @param algorithm integrity algorithm to add to SaProposal.
         * @return Builder of SaProposal.
         */
        public Builder addIntegrityAlgorithm(@IntegrityAlgorithm int algorithm) {
            // Construct IntegrityTransform and validate proposed algorithm during
            // construction.
            mProposedIntegrityAlgos.add(new IntegrityTransform(algorithm));
            return this;
        }

        /**
         * Adds a Diffie-Hellman Group to SA proposal being built.
         *
         * @param dhGroup to add to SaProposal.
         * @return Builder of SaProposal.
         */
        public Builder addDhGroup(@DhGroup int dhGroup) {
            // Construct DhGroupTransform and validate proposed dhGroup during
            // construction.
            mProposedDhGroups.add(new DhGroupTransform(dhGroup));
            return this;
        }

        /**
         * Validates, builds and returns the SaProposal
         *
         * @return SaProposal the validated SaProposal.
         * @throws IllegalArgumentException if SaProposal is invalid.
         * */
        public SaProposal buildOrThrow() {
            EncryptionTransform[] encryptionTransforms = buildEncryptAlgosOrThrow();
            PrfTransform[] prfTransforms = buildPrfsOrThrow();
            IntegrityTransform[] integrityTransforms = buildIntegAlgosOrThrow();
            DhGroupTransform[] dhGroupTransforms = buildDhGroupsOrThrow();

            // IKE library only supports negotiating ESP Child SA.
            int protocol = mIsIkeProposal ? IkePayload.PROTOCOL_ID_IKE : IkePayload.PROTOCOL_ID_ESP;

            return new SaProposal(
                    protocol,
                    encryptionTransforms,
                    prfTransforms,
                    integrityTransforms,
                    dhGroupTransforms);
        }
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

    /**
     * Check if the provided algorithm is a supported integrity algorithm.
     *
     * @param algorithm IKE standard integrity algorithm id.
     * @return true if the provided algorithm is a supported integrity algorithm.
     */
    public static boolean isSupportedIntegrityAlgorithm(@IntegrityAlgorithm int algorithm) {
        return SUPPORTED_INTEGRITY_ALGORITHM.contains(algorithm);
    }

    /**
     * Check if the provided group number is for a supported Diffie-Hellman Group.
     *
     * @param dhGroup IKE standard DH Group id.
     * @return true if the provided number is for a supported Diffie-Hellman Group.
     */
    public static boolean isSupportedDhGroup(@DhGroup int dhGroup) {
        return SUPPORTED_DH_GROUP.contains(dhGroup);
    }

    // TODO: Implement constructing SaProposal with a Builder that supports adding
    // encryption/integrity algorithms, prf, and DH Group. And add explanation of usage of
    // INTEGRITY_ALGORITHM_NONE and DH_GROUP_NONE.
}
