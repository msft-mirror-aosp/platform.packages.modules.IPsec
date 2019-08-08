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

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtPermanentIdReq;
import com.android.ike.eap.message.EapSimAttribute.AtVersionList;
import com.android.ike.eap.message.EapSimTypeData;
import com.android.ike.eap.message.EapSimTypeData.EapSimTypeDataDecoder.DecodeResult;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.StartState;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;


public class EapSimCreatedStateTest extends EapSimStateTest {
    private static final int EAP_SIM_START = 10;

    @Test
    public void testTransitionToStartState() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_SIM, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        List<EapSimAttribute> attributes = Arrays.asList(
                new AtVersionList(8, 1), new AtPermanentIdReq());
        DecodeResult decodeResult = new DecodeResult(new EapSimTypeData(EAP_SIM_START, attributes));
        when(mMockEapSimTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

        mEapSimMethodStateMachine.process(eapMessage);
        assertTrue(mEapSimMethodStateMachine.getState() instanceof StartState);

        // decoded in CreatedState and StartState
        verify(mMockEapSimTypeDataDecoder, times(2)).decode(eq(DUMMY_EAP_TYPE_DATA));
        verifyNoMoreInteractions(mMockEapSimTypeDataDecoder);
    }

    @Test
    public void testProcessIncorrectEapMethodType() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        EapResult result = mEapSimMethodStateMachine.process(eapMessage);
        EapError eapError = (EapError) result;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
    }
}
