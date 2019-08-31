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

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.EapData.EAP_NOTIFICATION;
import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_NOTIFICATION_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.telephony.TelephonyManager;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapSessionConfig.EapAkaConfig;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapAkaTypeData;
import com.android.ike.eap.message.simaka.EapAkaTypeData.EapAkaTypeDataDecoder;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData.DecodeResult;
import com.android.ike.eap.statemachine.EapMethodStateMachine.EapMethodState;

import org.junit.Before;
import org.junit.Test;

public class EapAkaStateTest {
    protected static final int SUB_ID = 1;
    protected static final String NOTIFICATION_MESSAGE = "test";
    protected static final byte[] DUMMY_EAP_TYPE_DATA = hexStringToByteArray("112233445566");

    protected TelephonyManager mMockTelephonyManager;
    protected EapAkaTypeDataDecoder mMockEapAkaTypeDataDecoder;

    protected EapAkaConfig mEapAkaConfig = new EapAkaConfig(SUB_ID, APPTYPE_USIM);
    protected EapAkaMethodStateMachine mEapAkaMethodStateMachine;

    @Before
    public void setUp() {
        mMockTelephonyManager = mock(TelephonyManager.class);
        mMockEapAkaTypeDataDecoder = mock(EapAkaTypeDataDecoder.class);

        when(mMockTelephonyManager.createForSubscriptionId(SUB_ID))
                .thenReturn(mMockTelephonyManager);

        mEapAkaMethodStateMachine =
                new EapAkaMethodStateMachine(
                        mMockTelephonyManager,
                        mEapAkaConfig,
                        mMockEapAkaTypeDataDecoder);

        verify(mMockTelephonyManager).createForSubscriptionId(SUB_ID);
    }

    @Test
    public void testProcessNotification() throws Exception {
        EapData eapData = new EapData(EAP_NOTIFICATION, NOTIFICATION_MESSAGE.getBytes());
        EapMessage notification = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);
        EapMethodState preNotification = (EapMethodState) mEapAkaMethodStateMachine.getState();

        EapResult result = mEapAkaMethodStateMachine.process(notification);
        assertEquals(preNotification, mEapAkaMethodStateMachine.getState());
        verifyNoMoreInteractions(mMockTelephonyManager, mMockEapAkaTypeDataDecoder);

        assertTrue(result instanceof EapResult.EapResponse);
        EapResult.EapResponse eapResponse = (EapResult.EapResponse) result;
        assertArrayEquals(EAP_RESPONSE_NOTIFICATION_PACKET, eapResponse.packet);
    }

    @Test
    public void testProcessInvalidDecodeResult() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);
        EapMethodState preProcess = (EapMethodState) mEapAkaMethodStateMachine.getState();

        AtClientErrorCode atClientErrorCode = AtClientErrorCode.UNABLE_TO_PROCESS;
        DecodeResult<EapAkaTypeData> decodeResult = new DecodeResult<>(atClientErrorCode);
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

        EapResult result = mEapAkaMethodStateMachine.process(eapMessage);
        assertEquals(preProcess, mEapAkaMethodStateMachine.getState());
        verify(mMockEapAkaTypeDataDecoder).decode(DUMMY_EAP_TYPE_DATA);
        verifyNoMoreInteractions(mMockTelephonyManager, mMockEapAkaTypeDataDecoder);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);
    }
}
