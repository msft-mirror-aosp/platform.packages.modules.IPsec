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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import org.junit.Test;

public final class ChildSessionOptionsTest {

    private static final int NUM_TS = 1;

    @Test
    public void testBuild() throws Exception {
        SaProposal saProposal =
                SaProposal.Builder.newChildSaProposalBuilder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12,
                                SaProposal.KEY_LEN_AES_128)
                        .build();
        ChildSessionOptions sessionOptions =
                new ChildSessionOptions.Builder().addSaProposal(saProposal).build();

        assertArrayEquals(new SaProposal[] {saProposal}, sessionOptions.getSaProposals());
        assertEquals(NUM_TS, sessionOptions.getLocalTrafficSelectors().length);
        assertEquals(NUM_TS, sessionOptions.getRemoteTrafficSelectors().length);
        assertFalse(sessionOptions.isTransportMode());
    }

    @Test
    public void testBuildWithoutSaProposal() throws Exception {
        try {
            new ChildSessionOptions.Builder().build();
            fail("Expected to fail due to the absence of SA proposal.");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testBuildWithIkeSaProposal() throws Exception {
        SaProposal saProposal =
                SaProposal.Builder.newIkeSaProposalBuilder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8,
                                SaProposal.KEY_LEN_AES_128)
                        .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        try {
            new ChildSessionOptions.Builder().addSaProposal(saProposal).build();
            fail("Expected to fail due to wrong type of SA proposal.");
        } catch (IllegalArgumentException expected) {
        }
    }
}
