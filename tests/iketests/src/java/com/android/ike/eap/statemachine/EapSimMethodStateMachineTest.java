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

import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CLIENT_ERROR_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_RESPONSE_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_IDENTITY;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.IDENTITY;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapSessionConfig.EapSimConfig;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtClientErrorCode;
import com.android.ike.eap.message.EapSimAttribute.AtIdentity;
import com.android.ike.eap.message.EapSimAttribute.AtSelectedVersion;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.CreatedState;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class EapSimMethodStateMachineTest {
    private static final int EAP_SIM_START = 10;
    private static final int SUB_ID = 1;

    private Context mContext;
    private EapSimConfig mEapSimConfig;
    private EapSimMethodStateMachine mEapSimMethodStateMachine;

    @Before
    public void setUp() {
        mContext = getInstrumentation().getContext();
        mEapSimConfig = new EapSimConfig(SUB_ID);
        mEapSimMethodStateMachine =
                new EapSimMethodStateMachine(mContext, mEapSimConfig, new SecureRandom());
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
}
