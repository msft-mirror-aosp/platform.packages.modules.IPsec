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

import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ENCR_DATA;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_IV;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_VERSION_LIST;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_START;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtAnyIdReq;
import com.android.ike.eap.message.EapSimAttribute.AtIdentity;
import com.android.ike.eap.message.EapSimAttribute.AtMac;
import com.android.ike.eap.message.EapSimAttribute.AtPermanentIdReq;
import com.android.ike.eap.message.EapSimAttribute.AtVersionList;
import com.android.ike.eap.message.EapSimTypeData;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.StartState;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;

public class EapSimStartStateTest extends EapSimStateTest {
    private static final String IMSI = "123456789012345";
    private static final String IDENTITY = "1" + IMSI;

    private StartState mStartState;
    private LinkedHashMap<Integer, EapSimAttribute> mAttributes;

    @Before
    public void setUp() {
        super.setUp();
        mStartState = mEapSimMethodStateMachine.new StartState(null);

        mAttributes = new LinkedHashMap<>();
    }

    @Test
    public void testIsValidStartAttributes() throws Exception {
        mAttributes.put(EAP_AT_VERSION_LIST, new AtVersionList(8, 1));
        mAttributes.put(EAP_AT_PERMANENT_ID_REQ, new AtPermanentIdReq());
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_START, mAttributes);
        assertTrue(mStartState.isValidStartAttributes(eapSimTypeData));
    }

    @Test
    public void testIsValidStartAttributesMissingVersionList() throws Exception {
        mAttributes.put(EAP_AT_PERMANENT_ID_REQ, new AtPermanentIdReq());
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_START, mAttributes);
        assertFalse(mStartState.isValidStartAttributes(eapSimTypeData));
    }

    @Test
    public void testIsValidStartAttributesMultipleIdRequests() throws Exception {
        mAttributes.put(EAP_AT_VERSION_LIST, new AtVersionList(8, 1));
        mAttributes.put(EAP_AT_PERMANENT_ID_REQ, new AtPermanentIdReq());
        mAttributes.put(EAP_AT_ANY_ID_REQ, new AtAnyIdReq());
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_START, mAttributes);
        assertFalse(mStartState.isValidStartAttributes(eapSimTypeData));
    }

    @Test
    public void testIsValidStartAttributesInvalidAttributes() throws Exception {
        mAttributes.put(EAP_AT_VERSION_LIST, new AtVersionList(8, 1));
        mAttributes.put(EAP_AT_PERMANENT_ID_REQ, new AtPermanentIdReq());
        mAttributes.put(EAP_AT_MAC, new AtMac());
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_START, mAttributes);
        assertFalse(mStartState.isValidStartAttributes(eapSimTypeData));

        mAttributes.remove(EAP_AT_MAC);
        mAttributes.put(EAP_AT_IV, null); // just need <K, V> pair in the map
        eapSimTypeData = new EapSimTypeData(EAP_SIM_START, mAttributes);
        assertFalse(mStartState.isValidStartAttributes(eapSimTypeData));

        mAttributes.remove(EAP_AT_IV);
        mAttributes.put(EAP_AT_ENCR_DATA, null); // just need <K, V> pair in the map
        eapSimTypeData = new EapSimTypeData(EAP_SIM_START, mAttributes);
        assertFalse(mStartState.isValidStartAttributes(eapSimTypeData));
    }

    @Test
    public void testAddIdentityAttributeToResponse() throws Exception {
        EapSimTypeData eapSimTypeData = new EapSimTypeData(
                EAP_SIM_START, Arrays.asList(new AtPermanentIdReq()));

        when(mMockTelephonyManager.getSubscriberId()).thenReturn(IMSI);

        AtIdentity atIdentity = mStartState.getIdentityResponse(eapSimTypeData);
        assertArrayEquals(IDENTITY.getBytes(), mStartState.mIdentity);
        verify(mMockTelephonyManager).getSubscriberId();
        assertArrayEquals(IDENTITY.getBytes(), atIdentity.identity);
        verifyNoMoreInteractions(mMockTelephonyManager);
    }

    @Test
    public void testAddIdentityAttributeToResponseNoIdRequest() throws Exception {
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_START, Arrays.asList());

        AtIdentity atIdentity = mStartState.getIdentityResponse(eapSimTypeData);
        assertNull(atIdentity);
        verifyNoMoreInteractions(mMockTelephonyManager);
    }
}
