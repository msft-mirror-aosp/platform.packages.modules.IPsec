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

import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CLIENT_ERROR_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_RESPONSE_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_CLIENT_ERROR;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_START;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AT_IDENTITY;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.IDENTITY;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtIdentity;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtSelectedVersion;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData;
import com.android.ike.eap.message.simaka.EapSimTypeData;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EapSimAkaMethodStateMachineTest {
    private EapSimAkaMethodStateMachine mStateMachine;

    @Before
    public void setUp() {
        mStateMachine = new EapSimAkaMethodStateMachine() {
            @Override
            EapSimAkaTypeData getEapSimAkaTypeData(AtClientErrorCode clientErrorCode) {
                return new EapSimTypeData(EAP_SIM_CLIENT_ERROR, Arrays.asList(clientErrorCode));
            }

            @Override
            EapSimAkaTypeData getEapSimAkaTypeData(
                    int eapSubtype,
                    List<EapSimAkaAttribute> attributes) {
                return new EapSimTypeData(eapSubtype, attributes);
            }

            @Override
            int getEapMethod() {
                return 0;
            }
        };
    }

    @Test
    public void testBuildClientErrorResponse() {
        AtClientErrorCode errorCode = AtClientErrorCode.UNSUPPORTED_VERSION;

        EapResult result =
                mStateMachine.buildClientErrorResponse(ID_INT, EAP_TYPE_SIM, errorCode);
        assertTrue(result instanceof EapResult.EapResponse);
        EapResult.EapResponse eapResponse = (EapResult.EapResponse) result;
        assertArrayEquals(EAP_SIM_CLIENT_ERROR_RESPONSE, eapResponse.packet);
    }

    @Test
    public void testBuildResponseMessage() throws Exception {
        List<EapSimAkaAttribute> attributes = new ArrayList<>();
        attributes.add(new AtSelectedVersion(1));
        attributes.add(new AtIdentity(AT_IDENTITY.length, IDENTITY));
        int identifier = ID_INT;

        EapResult result =
                mStateMachine.buildResponseMessage(
                        EAP_TYPE_SIM,
                        EAP_SIM_START,
                        identifier,
                        attributes);
        assertTrue(result instanceof EapResult);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_RESPONSE_PACKET, eapResponse.packet);
    }
}
