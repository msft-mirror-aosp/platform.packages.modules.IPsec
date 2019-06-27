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

package com.android.ike.eap.message;

import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_VERSION_LIST;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_START;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_START_SUBTYPE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.INVALID_SUBTYPE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SHORT_TYPE_DATA;
import static com.android.ike.eap.message.EapTestMessageDefinitions.TYPE_DATA_INVALID_ATTRIBUTE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.TYPE_DATA_INVALID_AT_RAND;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.message.EapSimAttribute.AtPermanentIdReq;
import com.android.ike.eap.message.EapSimAttribute.AtVersionList;
import com.android.ike.eap.message.EapSimTypeData.EapSimTypeDataDecoder;
import com.android.ike.eap.message.EapSimTypeData.EapSimTypeDataDecoder.DecodeResult;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;

public class EapSimTypeDataTest {
    private static final int UNABLE_TO_PROCESS_CODE = 0;
    private static final int INSUFFICIENT_CHALLENGES_CODE = 2;

    private EapSimTypeDataDecoder mEapSimTypeDataDecoder;

    @Before
    public void setUp() {
        mEapSimTypeDataDecoder = new EapSimTypeDataDecoder();
    }

    @Test
    public void testDecode() {
        DecodeResult result = mEapSimTypeDataDecoder.decode(EAP_SIM_START_SUBTYPE);

        assertTrue(result.isSuccessfulDecode());
        EapSimTypeData eapSimTypeData = result.eapSimTypeData;
        assertEquals(EAP_SIM_START, eapSimTypeData.eapSubtype);
        assertTrue(eapSimTypeData.attributeMap.containsKey(EAP_AT_VERSION_LIST));
        AtVersionList atVersionList = (AtVersionList)
                eapSimTypeData.attributeMap.get(EAP_AT_VERSION_LIST);
        assertEquals(Arrays.asList(1), atVersionList.versions);
        assertTrue(eapSimTypeData.attributeMap.containsKey(EAP_AT_PERMANENT_ID_REQ));

        // also check order of Map entries (needs to match input order)
        Iterator<Integer> itr = eapSimTypeData.attributeMap.keySet().iterator();
        assertEquals(EAP_AT_VERSION_LIST, (int) itr.next());
        assertEquals(EAP_AT_PERMANENT_ID_REQ, (int) itr.next());
        assertFalse(itr.hasNext());
    }

    @Test
    public void testDecodeNullTypeData() {
        DecodeResult result = mEapSimTypeDataDecoder.decode(null);
        assertFalse(result.isSuccessfulDecode());
        assertEquals(UNABLE_TO_PROCESS_CODE, result.atClientErrorCode.errorCode);
    }

    @Test
    public void testDecodeInvalidSubtype() {
        DecodeResult result = mEapSimTypeDataDecoder.decode(INVALID_SUBTYPE);
        assertFalse(result.isSuccessfulDecode());
        assertEquals(UNABLE_TO_PROCESS_CODE, result.atClientErrorCode.errorCode);

    }

    @Test
    public void testDecodeInvalidAtRand() {
        DecodeResult result = mEapSimTypeDataDecoder.decode(TYPE_DATA_INVALID_AT_RAND);
        assertFalse(result.isSuccessfulDecode());
        assertEquals(INSUFFICIENT_CHALLENGES_CODE, result.atClientErrorCode.errorCode);
    }

    @Test
    public void testDecodeShortPacket() {
        DecodeResult result = mEapSimTypeDataDecoder.decode(SHORT_TYPE_DATA);
        assertFalse(result.isSuccessfulDecode());
        assertEquals(UNABLE_TO_PROCESS_CODE, result.atClientErrorCode.errorCode);

    }

    @Test
    public void testDecodeInvalidEapAttribute() {
        DecodeResult result = mEapSimTypeDataDecoder.decode(TYPE_DATA_INVALID_ATTRIBUTE);
        assertFalse(result.isSuccessfulDecode());
        assertEquals(UNABLE_TO_PROCESS_CODE, result.atClientErrorCode.errorCode);
    }

    @Test
    public void testEncode() throws Exception {
        LinkedHashMap<Integer, EapSimAttribute> attributes = new LinkedHashMap<>();
        attributes.put(EAP_AT_VERSION_LIST, new AtVersionList(8, 1));
        attributes.put(EAP_AT_PERMANENT_ID_REQ, new AtPermanentIdReq());
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_START, attributes);

        byte[] result = eapSimTypeData.encode();
        assertArrayEquals(EAP_SIM_START_SUBTYPE, result);
    }
}
