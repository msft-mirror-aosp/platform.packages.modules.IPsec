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

import static com.android.internal.net.eap.message.EapData.EAP_TTLS;
import static com.android.internal.net.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.ID_INT;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.android.internal.net.eap.EapResult;
import com.android.internal.net.eap.EapResult.EapError;
import com.android.internal.net.eap.exceptions.EapInvalidRequestException;
import com.android.internal.net.eap.message.EapData;
import com.android.internal.net.eap.message.EapMessage;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData.EapTtlsTypeDataDecoder.DecodeResult;
import com.android.internal.net.eap.statemachine.EapTtlsMethodStateMachine.HandshakeState;

import org.junit.Test;

public class EapTtlsCreatedStateTest extends EapTtlsStateTest {

    @Test
    public void testStartRequest() throws Exception {
        EapData eapData = new EapData(EAP_TTLS, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        when(mMockTypeDataDecoder.decodeEapTtlsRequestPacket(eq(DUMMY_EAP_TYPE_DATA)))
                .thenReturn(
                        new DecodeResult(
                                EapTtlsTypeData.getEapTtlsTypeData(
                                        false, true, 0, 0, new byte[0])));

        mStateMachine.process(eapMessage);
        assertTrue(mStateMachine.getState() instanceof HandshakeState);
        verify(mMockTypeDataDecoder).decodeEapTtlsRequestPacket(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testUnexpectedRequest() throws Exception {
        EapData eapData = new EapData(EAP_TTLS, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        when(mMockTypeDataDecoder.decodeEapTtlsRequestPacket(eq(DUMMY_EAP_TYPE_DATA)))
                .thenReturn(
                        new DecodeResult(
                                EapTtlsTypeData.getEapTtlsTypeData(
                                        false, false, 0, 0, new byte[0])));

        EapResult eapResult = mStateMachine.process(eapMessage);
        EapError eapError = (EapError) eapResult;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
        verify(mMockTypeDataDecoder).decodeEapTtlsRequestPacket(eq(DUMMY_EAP_TYPE_DATA));
    }
}
