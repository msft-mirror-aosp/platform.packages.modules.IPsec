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

package com.android.ike.eap.statemachine;

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.NONCE_MT;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.EapSimAttribute.AtNonceMt;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.ChallengeState;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.FinalState;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

public class EapSimChallengeStateTest extends EapSimStateTest {
    private static final List<Integer> VERSIONS = Arrays.asList(1);
    private static final byte[] MSK = hexStringToByteArray(
            "00112233445566778899AABBCCDDEEFF"
            + "00112233445566778899AABBCCDDEEFF"
            + "00112233445566778899AABBCCDDEEFF"
            + "00112233445566778899AABBCCDDEEFF");
    private static final byte[] EMSK = hexStringToByteArray(
            "FFEEDDCCBBAA99887766554433221100"
            + "FFEEDDCCBBAA99887766554433221100"
            + "FFEEDDCCBBAA99887766554433221100"
            + "FFEEDDCCBBAA99887766554433221100");

    private AtNonceMt mAtNonceMt;
    private ChallengeState mChallengeState;

    @Override
    public void setUp() {
        super.setUp();

        try {
            mAtNonceMt = new AtNonceMt(NONCE_MT);
        } catch (EapSimInvalidAttributeException ex) {
            // this will never happen
        }
        mChallengeState = mEapSimMethodStateMachine.new ChallengeState(VERSIONS, mAtNonceMt);
        mEapSimMethodStateMachine.transitionTo(mChallengeState);
    }

    @Test
    public void testProcessSuccess() throws Exception {
        System.arraycopy(MSK, 0, mChallengeState.mMsk, 0, MSK.length);
        System.arraycopy(EMSK, 0, mChallengeState.mEmsk, 0, EMSK.length);

        EapMessage input = new EapMessage(EAP_CODE_SUCCESS, ID_INT, null);
        EapResult result = mEapSimMethodStateMachine.process(input);
        assertTrue(mEapSimMethodStateMachine.getState() instanceof FinalState);

        EapSuccess eapSuccess = (EapSuccess) result;
        assertArrayEquals(MSK, eapSuccess.msk);
        assertArrayEquals(EMSK, eapSuccess.emsk);
    }

    @Test
    public void testProcessFailure() throws Exception {
        EapMessage input = new EapMessage(EAP_CODE_FAILURE, ID_INT, null);
        EapResult result = mEapSimMethodStateMachine.process(input);
        assertTrue(mEapSimMethodStateMachine.getState() instanceof FinalState);

        assertTrue(result instanceof EapFailure);
    }
}
