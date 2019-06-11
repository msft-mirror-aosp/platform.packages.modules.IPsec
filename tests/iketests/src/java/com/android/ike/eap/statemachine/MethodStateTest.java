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

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_SIM_START_PACKET;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import com.android.ike.eap.statemachine.EapStateMachine.MethodState;

import org.junit.Before;
import org.junit.Test;

public class MethodStateTest extends EapStateTest {
    private static final int UNSUPPORTED_EAP_TYPE = 0xFF;

    private Context mContext;
    private EapStateMachine mEapStateMachine;

    @Before
    @Override
    public void setUp() {
        mContext = getInstrumentation().getContext();
        mEapStateMachine = new EapStateMachine(mContext);
        mEapState = mEapStateMachine.new MethodState(EAP_TYPE_AKA);
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
}
