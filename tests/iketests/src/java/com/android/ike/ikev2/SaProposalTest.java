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

package com.android.ike.ikev2;

import static org.junit.Assert.fail;

import com.android.ike.ikev2.SaProposal.Builder;

import org.junit.Test;

public final class SaProposalTest {
    @Test
    public void testBuildEncryptAlgosWithNoAlgorithm() throws Exception {
        Builder builder = Builder.newIkeSaProposalBuilder();
        try {
            builder.buildOrThrow();
            fail("Encryption algorithm is not provided.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildEncryptAlgosWithUnrecognizedAlgorithm() throws Exception {
        Builder builder = Builder.newIkeSaProposalBuilder();
        try {
            builder.addEncryptionAlgorithm(-1);
            fail("Encryption algorithm is not recognized.");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testBuildEncryptAlgosWithTwoModes() throws Exception {
        Builder builder = Builder.newIkeSaProposalBuilder();
        try {
            builder.addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_3DES)
                    .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12);
            fail("Expect failure when normal and combined-mode ciphers are proposed together.");
        } catch (IllegalArgumentException expected) {

        }
    }
}
