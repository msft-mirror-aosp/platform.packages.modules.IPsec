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

import static androidx.test.InstrumentationRegistry.getInstrumentation;

import static com.android.internal.net.TestUtils.hexStringToByteArray;
import static com.android.internal.net.eap.EapTestUtils.getDummyEapSessionConfig;
import static com.android.internal.net.eap.message.EapData.EAP_NOTIFICATION;
import static com.android.internal.net.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.internal.net.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.internal.net.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_NOTIFICATION_PACKET;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.ID_INT;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import android.content.Context;
import android.net.eap.EapSessionConfig;
import android.net.eap.EapSessionConfig.EapTtlsConfig;

import com.android.internal.net.eap.EapResult;
import com.android.internal.net.eap.EapResult.EapError;
import com.android.internal.net.eap.EapResult.EapFailure;
import com.android.internal.net.eap.EapResult.EapResponse;
import com.android.internal.net.eap.exceptions.EapInvalidRequestException;
import com.android.internal.net.eap.message.EapData;
import com.android.internal.net.eap.message.EapMessage;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData.EapTtlsTypeDataDecoder;
import com.android.internal.net.eap.statemachine.EapMethodStateMachine.EapMethodState;
import com.android.internal.net.eap.statemachine.EapMethodStateMachine.FinalState;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class EapTtlsStateTest {

    Context mContext;
    SecureRandom mMockSecureRandom;
    EapTtlsTypeDataDecoder mMockTypeDataDecoder;

    EapSessionConfig mEapSessionConfig;
    EapTtlsConfig mEapTtlsConfig;
    EapTtlsMethodStateMachine mStateMachine;

    static final String NOTIFICATION_MESSAGE = "test";
    static final byte[] DUMMY_EAP_TYPE_DATA = hexStringToByteArray("112233445566");

    @Before
    public void setUp() {
        mContext = getInstrumentation().getContext();
        mMockSecureRandom = mock(SecureRandom.class);
        mMockTypeDataDecoder = mock(EapTtlsTypeDataDecoder.class);

        mEapTtlsConfig = new EapTtlsConfig(null);

        mStateMachine =
                new EapTtlsMethodStateMachine(
                        mContext,
                        getDummyEapSessionConfig(),
                        mEapTtlsConfig,
                        mMockSecureRandom,
                        mMockTypeDataDecoder);
    }

    @Test
    public void testHandleEapFailureNotification() throws Exception {
        EapResult result = mStateMachine.process(new EapMessage(EAP_CODE_FAILURE, ID_INT, null));
        assertTrue(result instanceof EapFailure);
        assertTrue(mStateMachine.getState() instanceof FinalState);
    }

    @Test
    public void testHandleEapSuccessNotification() throws Exception {
        EapResult result = mStateMachine.process(new EapMessage(EAP_CODE_SUCCESS, ID_INT, null));
        EapError eapError = (EapError) result;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
    }

    @Test
    public void testHandleEapNotification() throws Exception {
        EapData eapData = new EapData(EAP_NOTIFICATION, NOTIFICATION_MESSAGE.getBytes());
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);
        EapMethodState preNotification = (EapMethodState) mStateMachine.getState();

        EapResult result = mStateMachine.process(eapMessage);
        assertEquals(preNotification, mStateMachine.getState());

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_RESPONSE_NOTIFICATION_PACKET, eapResponse.packet);
    }
}
