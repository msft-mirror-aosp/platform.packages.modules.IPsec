/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.internal.net.eap.statemachine;

import static com.android.internal.net.TestUtils.hexStringToByteArray;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.ID_INT;

import static org.junit.Assert.assertArrayEquals;

import com.android.internal.net.eap.statemachine.EapTtlsMethodStateMachine.HandshakeState;

import org.junit.Before;
import org.junit.Test;

public class EapTtlsHandshakeStateTest extends EapTtlsStateTest {

    private static final byte[] DUMMY_EAP_IDENTITY_AVP =
            hexStringToByteArray(
                    "0000004F" + "40" + "00000D" // AVP Code | AVP Flags | AVP Length
                            + "0210000501" // EAP-Response/Identity
                            + "000000"); // Padding

    private HandshakeState mHandshakeState;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        mHandshakeState = mStateMachine.new HandshakeState();
        mStateMachine.transitionTo(mHandshakeState);
    }

    @Test
    public void testBuildEapIdentityResponseAvp() throws Exception {
        assertArrayEquals(
                DUMMY_EAP_IDENTITY_AVP, mHandshakeState.buildEapIdentityResponseAvp(ID_INT));
    }
}
