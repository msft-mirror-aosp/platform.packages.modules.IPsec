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
import static com.android.ike.TestUtils.stringToHexString;
import static com.android.ike.eap.EapTestUtils.getDummyEapSessionConfig;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_AKA_IDENTITY_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_IDENTITY_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_NOTIFICATION_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_IDENTITY_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_NOTIFICATION_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.statemachine.EapStateMachine.IdentityState;
import com.android.ike.eap.statemachine.EapStateMachine.MethodState;

import org.junit.Before;
import org.junit.Test;

public class IdentityStateTest extends EapStateTest {
    private static final String IDENTITY_STRING = "identity";
    private static final String IDENTITY_HEX_STRING =
            stringToHexString(IDENTITY_STRING);
    private static final byte[] EXPECTED_IDENTITY = IDENTITY_STRING.getBytes();
    private static final byte[] EXPECTED_IDENTITY_RESPONSE =
            hexStringToByteArray("02" + ID + "000D01" + IDENTITY_HEX_STRING);

    private EapStateMachine mEapStateMachineMock;

    @Before
    @Override
    public void setUp() {
        mEapStateMachineMock = mock(EapStateMachine.class);
        mEapSessionConfig = getDummyEapSessionConfig();
        mEapState = mEapStateMachineMock.new IdentityState();
    }

    @Test
    public void testGetIdentityMessage() {
        EapResult result = ((IdentityState) mEapState)
                .getIdentityResponse(ID_INT, EXPECTED_IDENTITY);

        assertTrue(result instanceof EapResponse);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EXPECTED_IDENTITY_RESPONSE, eapResponse.packet);
        verifyNoMoreInteractions(mEapStateMachineMock);
    }

    @Test
    public void testProcess() {
        EapResult eapResult = mEapState.process(EAP_REQUEST_IDENTITY_PACKET);

        assertTrue(eapResult instanceof EapResponse);
        EapResponse eapResponse = (EapResponse) eapResult;
        assertArrayEquals(EAP_RESPONSE_IDENTITY_PACKET, eapResponse.packet);
        verifyNoMoreInteractions(mEapStateMachineMock);
    }

    @Test
    public void testProcessNotificationRequest() {
        EapResult eapResult = mEapState.process(EAP_REQUEST_NOTIFICATION_PACKET);

        // state shouldn't change after Notification request
        assertTrue(eapResult instanceof EapResponse);
        EapResponse eapResponse = (EapResponse) eapResult;
        assertArrayEquals(EAP_RESPONSE_NOTIFICATION_PACKET, eapResponse.packet);
        verifyNoMoreInteractions(mEapStateMachineMock);
    }

    @Test
    public void testProcessAkaIdentity() {
        when(mEapStateMachineMock.getEapSessionConfig()).thenReturn(mEapSessionConfig);

        mEapState.process(EAP_REQUEST_AKA_IDENTITY_PACKET);

        // EapStateMachine should change to MethodState for method-type packet
        verify(mEapStateMachineMock).transitionAndProcess(
                any(MethodState.class), eq(EAP_REQUEST_AKA_IDENTITY_PACKET));
        verify(mEapStateMachineMock).getEapSessionConfig();
        verifyNoMoreInteractions(mEapStateMachineMock);
    }
}
