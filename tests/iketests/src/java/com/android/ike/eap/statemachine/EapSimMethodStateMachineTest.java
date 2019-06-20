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

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapSimAttribute.AtNotification.GENERAL_FAILURE_POST_CHALLENGE;
import static com.android.ike.eap.message.EapSimAttribute.AtNotification.GENERAL_FAILURE_PRE_CHALLENGE;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_CHALLENGE;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_NOTIFICATION;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_START;
import static com.android.ike.eap.message.EapTestMessageDefinitions.COMPUTED_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CLIENT_ERROR_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CLIENT_ERROR_UNABLE_TO_PROCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_NOTIFICATION_REQUEST_WITH_EMPTY_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_NOTIFICATION_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_NOTIFICATION_RESPONSE_WITH_EMPTY_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_NOTIFICATION_RESPONSE_WITH_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_RESPONSE_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MAC_INPUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ORIGINAL_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.RETURNED_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SRES_BYTES;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_IDENTITY;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.IDENTITY;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.NONCE_MT;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_1_BYTES;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_2_BYTES;
import static com.android.ike.eap.statemachine.EapSimStateTest.EAP_CODE_REQUEST;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.content.Context;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapSessionConfig.EapSimConfig;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtClientErrorCode;
import com.android.ike.eap.message.EapSimAttribute.AtIdentity;
import com.android.ike.eap.message.EapSimAttribute.AtMac;
import com.android.ike.eap.message.EapSimAttribute.AtNotification;
import com.android.ike.eap.message.EapSimAttribute.AtRand;
import com.android.ike.eap.message.EapSimAttribute.AtSelectedVersion;
import com.android.ike.eap.message.EapSimTypeData;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.CreatedState;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.EapSimState;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;

public class EapSimMethodStateMachineTest {
    private static final int SUB_ID = 1;
    private static final int AT_RAND_LEN = 36;
    protected static final byte[] DUMMY_EAP_TYPE_DATA = hexStringToByteArray("112233445566");

    private Context mContext;
    private EapSimConfig mEapSimConfig;
    private EapSimMethodStateMachine mEapSimMethodStateMachine;

    @Before
    public void setUp() {
        mContext = getInstrumentation().getContext();
        mEapSimConfig = new EapSimConfig(SUB_ID);
        mEapSimMethodStateMachine =
                spy(new EapSimMethodStateMachine(mContext, mEapSimConfig, new SecureRandom()));
    }

    @Test
    public void testEapSimMethodStateMachineStartState() {
        assertTrue(mEapSimMethodStateMachine.getState() instanceof CreatedState);
    }

    @Test
    public void testGetMethod() {
        assertEquals(EAP_TYPE_SIM, mEapSimMethodStateMachine.getEapMethod());
    }

    @Test
    public void testBuildResponseMessage() throws Exception {
        List<EapSimAttribute> attributes = new ArrayList<>();
        attributes.add(new AtSelectedVersion(1));
        attributes.add(new AtIdentity(AT_IDENTITY.length, IDENTITY));
        int identifier = ID_INT;

        EapResult result = mEapSimMethodStateMachine
                .buildResponseMessage(EAP_SIM_START, identifier, attributes);
        assertTrue(result instanceof EapResult);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_RESPONSE_PACKET, eapResponse.packet);
    }

    @Test
    public void testBuildClientErrorResponse() {
        AtClientErrorCode errorCode = AtClientErrorCode.UNSUPPORTED_VERSION;
        int identifier = ID_INT;

        EapResult result = mEapSimMethodStateMachine
                .buildClientErrorResponse(identifier, errorCode);
        assertTrue(result instanceof EapResponse);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CLIENT_ERROR_RESPONSE, eapResponse.packet);
    }

    @Test
    public void testGetMac() throws Exception {
        AtMac atMac = new AtMac(ORIGINAL_MAC);
        AtRand atRand = new AtRand(AT_RAND_LEN, RAND_1_BYTES, RAND_2_BYTES);
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(EAP_SIM_CHALLENGE, Arrays.asList(atRand, atMac));

        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(MAC_INPUT))).thenReturn(COMPUTED_MAC);
        mEapSimMethodStateMachine.mMacAlgorithm = mockMac;

        byte[] mac =
                mEapSimMethodStateMachine.getMac(
                        EAP_CODE_REQUEST,
                        ID_INT,
                        eapSimTypeData,
                        NONCE_MT);
        assertArrayEquals(RETURNED_MAC, mac);
        AtMac postCalculationAtMac = (AtMac) eapSimTypeData.attributeMap.get(EAP_AT_MAC);
        assertArrayEquals(ORIGINAL_MAC, postCalculationAtMac.mac);

        verify(mockMac).doFinal(eq(MAC_INPUT));
        verifyNoMoreInteractions(mockMac);
    }

    @Test
    public void testGetMacNoMacAlgorithm() throws Exception {
        try {
            mEapSimMethodStateMachine.getMac(
                    EAP_CODE_REQUEST,
                    ID_INT,
                    null,
                    null);
            fail("Expected IllegalStateException for getMac when Mac not set");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testBuildResponseMessageWithMac() {
        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT))).thenReturn(COMPUTED_MAC);
        mEapSimMethodStateMachine.mMacAlgorithm = mockMac;

        EapResult result = mEapSimMethodStateMachine.buildResponseMessageWithMac(
                ID_INT,
                EAP_SIM_CHALLENGE,
                SRES_BYTES);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC, eapResponse.packet);
        verify(mockMac).doFinal(eq(EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT));
        verifyNoMoreInteractions(mockMac);
    }

    @Test
    public void testHandleEapSimNotificationPreChallenge() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(
                        EAP_SIM_NOTIFICATION,
                        Arrays.asList(new AtNotification(GENERAL_FAILURE_PRE_CHALLENGE)));

        EapResult result =
                mEapSimMethodStateMachine.handleEapSimNotification(
                        true,
                        ID_INT,
                        eapSimTypeData);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_NOTIFICATION_RESPONSE, eapResponse.packet);
        assertTrue(mEapSimMethodStateMachine.mHasReceivedSimNotification);
        verify(mEapSimMethodStateMachine, never()).transitionTo(any(EapSimState.class));
    }

    @Test
    public void testHandleEapSimNotificationPreChallengeInvalidPBit() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(
                        EAP_SIM_NOTIFICATION,
                        Arrays.asList(new AtNotification(GENERAL_FAILURE_POST_CHALLENGE)));

        EapResult result =
                mEapSimMethodStateMachine.handleEapSimNotification(
                        true,
                        ID_INT,
                        eapSimTypeData);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);
        verify(mEapSimMethodStateMachine, never()).transitionTo(any(EapSimState.class));
    }

    @Test
    public void testHandleEapSimNotificationMultipleNotifications() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(
                        EAP_SIM_NOTIFICATION,
                        Arrays.asList(new AtNotification(GENERAL_FAILURE_PRE_CHALLENGE)));

        mEapSimMethodStateMachine.handleEapSimNotification(
                true,
                ID_INT,
                eapSimTypeData);
        EapResult result = mEapSimMethodStateMachine.handleEapSimNotification(
                true,
                ID_INT,
                eapSimTypeData);

        EapError eapError = (EapError) result;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
        assertTrue(mEapSimMethodStateMachine.mHasReceivedSimNotification);
        verify(mEapSimMethodStateMachine, never()).transitionTo(any(EapSimState.class));
    }

    @Test
    public void testHandleEapSimNotificationInvalidAtMac() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(
                        EAP_SIM_NOTIFICATION,
                        Arrays.asList(
                                new AtNotification(GENERAL_FAILURE_PRE_CHALLENGE),
                                new AtMac()));

        EapResult result = mEapSimMethodStateMachine.handleEapSimNotification(
                true,
                ID_INT,
                eapSimTypeData);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);
        verify(mEapSimMethodStateMachine, never()).transitionTo(any(EapSimState.class));
    }

    @Test
    public void testHandleEapSimNotificationPostChallenge() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(
                        EAP_SIM_NOTIFICATION,
                        Arrays.asList(
                                new AtNotification(GENERAL_FAILURE_POST_CHALLENGE),
                                new AtMac(ORIGINAL_MAC)));

        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(EAP_SIM_NOTIFICATION_REQUEST_WITH_EMPTY_MAC)))
                .thenReturn(ORIGINAL_MAC);
        when(mockMac.doFinal(eq(EAP_SIM_NOTIFICATION_RESPONSE_WITH_EMPTY_MAC)))
                .thenReturn(COMPUTED_MAC);
        mEapSimMethodStateMachine.mMacAlgorithm = mockMac;

        EapResult result = mEapSimMethodStateMachine.handleEapSimNotification(
                false,
                ID_INT,
                eapSimTypeData);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_NOTIFICATION_RESPONSE_WITH_MAC, eapResponse.packet);
        assertTrue(mEapSimMethodStateMachine.mHasReceivedSimNotification);
        verify(mEapSimMethodStateMachine, never()).transitionTo(any(EapSimState.class));

        verify(mockMac).doFinal(eq(EAP_SIM_NOTIFICATION_REQUEST_WITH_EMPTY_MAC));
        verify(mockMac).doFinal(eq(EAP_SIM_NOTIFICATION_RESPONSE_WITH_EMPTY_MAC));
        verifyNoMoreInteractions(mockMac);
    }

    @Test
    public void testHandleEapSimNotificationPostChallengeInvalidAtMac() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(
                        EAP_SIM_NOTIFICATION,
                        Arrays.asList(new AtNotification(GENERAL_FAILURE_POST_CHALLENGE)));

        EapResult result = mEapSimMethodStateMachine.handleEapSimNotification(
                false,
                ID_INT,
                eapSimTypeData);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);
        verify(mEapSimMethodStateMachine, never()).transitionTo(any(EapSimState.class));
    }
}
