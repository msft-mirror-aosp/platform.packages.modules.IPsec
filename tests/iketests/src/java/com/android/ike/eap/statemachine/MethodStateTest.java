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

import static androidx.test.InstrumentationRegistry.getInstrumentation;

import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.ike.eap.message.EapMessage.EAP_HEADER_LENGTH;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_FAILURE_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_SIM_START_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SUCCESS_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.EapSessionConfig;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.statemachine.EapStateMachine.FailureState;
import com.android.ike.eap.statemachine.EapStateMachine.MethodState;
import com.android.ike.eap.statemachine.EapStateMachine.SuccessState;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;

import java.security.SecureRandom;

public class MethodStateTest extends EapStateTest {
    private static final int UNSUPPORTED_EAP_TYPE = 0xFF;
    private static final int SUB_ID = 1;

    private EapStateMachine mEapStateMachine;

    @Before
    @Override
    public void setUp() {
        mContext = getInstrumentation().getContext();
        mEapSessionConfig = new EapSessionConfig.Builder().setEapSimConfig(SUB_ID).build();
        mEapStateMachine = new EapStateMachine(mContext, mEapSessionConfig, new SecureRandom());
        mEapState = mEapStateMachine.new MethodState(EAP_TYPE_SIM);
        mEapStateMachine.transitionTo(mEapState);
    }

    @Test
    public void testProcessUnsupportedEapType() {
        try {
            mEapState = mEapStateMachine.new MethodState(UNSUPPORTED_EAP_TYPE);
            fail("Expected IllegalArgumentException for making MethodState with invalid type");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testProcessTransitionsToEapSim() {
        mEapStateMachine.process(EAP_REQUEST_SIM_START_PACKET);

        assertTrue(mEapStateMachine.getState() instanceof MethodState);
        MethodState methodState = (MethodState) mEapStateMachine.getState();
        assertTrue(methodState.mEapMethodStateMachine instanceof EapSimMethodStateMachine);
    }

    @Test
    public void testProcessTransitionToSuccessState() {
        EapSuccess eapSuccess = new EapSuccess(MSK, EMSK);

        ArgumentMatcher<EapMessage> eapSuccessMatcher = msg ->
                msg.eapCode == EAP_CODE_SUCCESS
                        && msg.eapIdentifier == ID_INT
                        && msg.eapLength == EAP_HEADER_LENGTH
                        && msg.eapData == null;

        EapMethodStateMachine mockEapMethodStateMachine = mock(EapMethodStateMachine.class);
        when(mockEapMethodStateMachine.process(argThat(eapSuccessMatcher))).thenReturn(eapSuccess);
        mEapStateMachine.transitionTo(mEapStateMachine.new MethodState(mockEapMethodStateMachine));

        mEapStateMachine.process(EAP_SUCCESS_PACKET);
        verify(mockEapMethodStateMachine).process(argThat(eapSuccessMatcher));
        assertTrue(mEapStateMachine.getState() instanceof SuccessState);
        verifyNoMoreInteractions(mockEapMethodStateMachine);
    }

    @Test
    public void testProcessTransitionToFailureState() {
        EapFailure eapFailure = new EapFailure();

        ArgumentMatcher<EapMessage> eapSuccessMatcher = msg ->
                msg.eapCode == EAP_CODE_FAILURE
                        && msg.eapIdentifier == ID_INT
                        && msg.eapLength == EAP_HEADER_LENGTH
                        && msg.eapData == null;

        EapMethodStateMachine mockEapMethodStateMachine = mock(EapMethodStateMachine.class);
        when(mockEapMethodStateMachine.process(argThat(eapSuccessMatcher))).thenReturn(eapFailure);
        mEapStateMachine.transitionTo(mEapStateMachine.new MethodState(mockEapMethodStateMachine));

        mEapStateMachine.process(EAP_FAILURE_PACKET);
        verify(mockEapMethodStateMachine).process(argThat(eapSuccessMatcher));
        assertTrue(mEapStateMachine.getState() instanceof FailureState);
        verifyNoMoreInteractions(mockEapMethodStateMachine);
    }
}
