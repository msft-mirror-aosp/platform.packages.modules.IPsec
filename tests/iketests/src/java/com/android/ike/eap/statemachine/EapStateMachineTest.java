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
import static com.android.ike.eap.message.EapData.NAK_DATA;
import static com.android.ike.eap.message.EapMessage.EAP_HEADER_LENGTH;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.exceptions.EapInvalidPacketLengthException;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.statemachine.EapStateMachine.CreatedState;
import com.android.ike.eap.statemachine.EapStateMachine.FailureState;
import com.android.ike.eap.statemachine.EapStateMachine.IdentityState;
import com.android.ike.eap.statemachine.EapStateMachine.MethodState;
import com.android.ike.eap.statemachine.EapStateMachine.SuccessState;

import org.junit.Test;

public class EapStateMachineTest {
    private static final String EAP_SUCCESS_STRING = "03100004";
    private static final byte[] EAP_SUCCESS_PACKET = hexStringToByteArray(EAP_SUCCESS_STRING);

    private static final String EAP_DECODE_FAILURE_STRING = "0110000A"; // incorrect length
    private static final byte[] EAP_DECODE_FAILURE_PACKET = hexStringToByteArray(
            EAP_DECODE_FAILURE_STRING);

    private static final String EAP_UNSUPPORTED_TYPE_STRING = "01100005FF";
    private static final byte[] EAP_UNSUPPORTED_TYPE_PACKET = hexStringToByteArray(
            EAP_UNSUPPORTED_TYPE_STRING);

    @Test
    public void testEapStateMachineStartState() {
        EapStateMachine eapStateMachine = new EapStateMachine();
        assertTrue(eapStateMachine.getState() instanceof CreatedState);
    }

    @Test
    public void testSuccessStateProcessFails() {
        SuccessState successState = new EapStateMachine().new SuccessState();
        EapResult result = successState.process(EAP_SUCCESS_PACKET);
        assertTrue(result instanceof EapError);

        EapError eapError = (EapError) result;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
    }

    @Test
    public void testFailureStateProcessFails() {
        FailureState failureState = new EapStateMachine().new FailureState();
        EapResult result = failureState.process(EAP_SUCCESS_PACKET);
        assertTrue(result instanceof EapError);

        EapError eapError = (EapError) result;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
    }

    @Test
    public void testProcessUnsupportedEapDataType() {
        CreatedState createdState = new EapStateMachine().new CreatedState();
        assertNakResponse(createdState.process(EAP_UNSUPPORTED_TYPE_PACKET));

        IdentityState identityState = new EapStateMachine().new IdentityState();
        assertNakResponse(identityState.process(EAP_UNSUPPORTED_TYPE_PACKET));

        MethodState methodState = new EapStateMachine().new MethodState();
        assertNakResponse(methodState.process(EAP_UNSUPPORTED_TYPE_PACKET));
    }

    private void assertNakResponse(EapResult result) {
        assertTrue(result instanceof EapResponse);
        EapResponse eapResponse = (EapResponse) result;

        int expectedLength = EAP_HEADER_LENGTH + NAK_DATA.getLength();
        assertEquals(expectedLength, eapResponse.packet.length);
    }

    @Test
    public void testProcessDecodeFailure() {
        CreatedState createdState = new EapStateMachine().new CreatedState();
        assertEapError(createdState.process(EAP_DECODE_FAILURE_PACKET),
                EapInvalidPacketLengthException.class);

        IdentityState identityState = new EapStateMachine().new IdentityState();
        assertEapError(identityState.process(EAP_DECODE_FAILURE_PACKET),
                EapInvalidPacketLengthException.class);

        MethodState methodState = new EapStateMachine().new MethodState();
        assertEapError(methodState.process(EAP_DECODE_FAILURE_PACKET),
                EapInvalidPacketLengthException.class);
    }

    private void assertEapError(EapResult result, Class<? extends Exception> expectedCause) {
        assertTrue(result instanceof EapError);

        EapError eapError = (EapError) result;
        assertTrue(expectedCause.isInstance(eapError.cause));
    }
}
