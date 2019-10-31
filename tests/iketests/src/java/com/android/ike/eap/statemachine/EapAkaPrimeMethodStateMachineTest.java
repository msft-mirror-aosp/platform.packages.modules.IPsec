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

import static com.android.ike.eap.statemachine.EapAkaPrimeMethodStateMachine.K_AUT_LEN;
import static com.android.ike.eap.statemachine.EapAkaPrimeMethodStateMachine.K_RE_LEN;
import static com.android.ike.eap.statemachine.EapSimAkaMethodStateMachine.KEY_LEN;
import static com.android.ike.eap.statemachine.EapSimAkaMethodStateMachine.SESSION_KEY_LENGTH;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.statemachine.EapAkaMethodStateMachine.CreatedState;

import org.junit.Test;

public class EapAkaPrimeMethodStateMachineTest extends EapAkaPrimeTest {
    @Test
    public void testEapAkaPrimeMethodStateMachineStartState() {
        assertTrue(mStateMachine.getState() instanceof CreatedState);
    }

    @Test
    public void testKeyLengths() {
        assertEquals(KEY_LEN, mStateMachine.getKEncrLength());
        assertEquals(K_AUT_LEN, mStateMachine.getKAutLength());
        assertEquals(K_RE_LEN, mStateMachine.getKReLen());
        assertEquals(SESSION_KEY_LENGTH, mStateMachine.getMskLength());
        assertEquals(SESSION_KEY_LENGTH, mStateMachine.getEmskLength());
    }
}
