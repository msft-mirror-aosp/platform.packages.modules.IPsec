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

package android.net.ipsec.test.ike;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import org.junit.Test;

public final class ChildSessionParamsTest {
    private static final int NUM_TS = 1;

    @Test
    public void testBuild() throws Exception {
        ChildSaProposal saProposal =
                new ChildSaProposal.Builder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12,
                                SaProposal.KEY_LEN_AES_128)
                        .build();
        ChildSessionParams sessionParams =
                new TunnelModeChildSessionParams.Builder().addSaProposal(saProposal).build();

        assertArrayEquals(new SaProposal[] {saProposal}, sessionParams.getSaProposalsInternal());
        assertEquals(NUM_TS, sessionParams.getLocalTrafficSelectorsInternal().length);
        assertEquals(NUM_TS, sessionParams.getRemoteTrafficSelectorsInternal().length);
        assertFalse(sessionParams.isTransportMode());
    }

    @Test
    public void testBuildWithoutSaProposal() throws Exception {
        try {
            new TunnelModeChildSessionParams.Builder().build();
            fail("Expected to fail due to the absence of SA proposal.");
        } catch (IllegalArgumentException expected) {
        }
    }
}
