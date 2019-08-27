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

import static android.telephony.TelephonyManager.APPTYPE_USIM;

import static androidx.test.InstrumentationRegistry.getInstrumentation;

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import com.android.ike.eap.EapSessionConfig.EapAkaConfig;
import com.android.ike.eap.statemachine.EapAkaMethodStateMachine.CreatedState;

import org.junit.Before;
import org.junit.Test;

public class EapAkaMethodStateMachineTest {
    private static final int SUB_ID = 1;

    private Context mContext;
    private EapAkaConfig mEapAkaConfig;
    private EapAkaMethodStateMachine mEapAkaMethodStateMachine;

    @Before
    public void setUp() {
        mContext = getInstrumentation().getContext();
        mEapAkaConfig = new EapAkaConfig(SUB_ID, APPTYPE_USIM);
        mEapAkaMethodStateMachine = new EapAkaMethodStateMachine(mContext, mEapAkaConfig);
    }

    @Test
    public void testEapAkaMethodStateMachineStartState() {
        assertTrue(mEapAkaMethodStateMachine.getState() instanceof CreatedState);
    }

    @Test
    public void testGetEapMethod() {
        assertEquals(EAP_TYPE_AKA, mEapAkaMethodStateMachine.getEapMethod());
    }
}
