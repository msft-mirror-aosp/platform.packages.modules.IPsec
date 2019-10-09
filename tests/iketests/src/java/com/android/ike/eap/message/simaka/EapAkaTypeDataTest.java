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

package com.android.ike.eap.message.simaka;

import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_CHALLENGE_RESPONSE_MAC_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_CHALLENGE_RESPONSE_TYPE_DATA;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_IDENTITY_REQUEST;
import static com.android.ike.eap.message.EapTestMessageDefinitions.INVALID_SUBTYPE;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_IDENTITY;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_RES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RES_BYTES;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.message.simaka.EapAkaTypeData.EapAkaTypeDataDecoder;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtAnyIdReq;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtMac;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtRes;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData.DecodeResult;

import org.junit.Before;
import org.junit.Test;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

public class EapAkaTypeDataTest {
    private static final int UNABLE_TO_PROCESS_CODE = 0;

    private EapAkaTypeDataDecoder mEapAkaTypeDataDecoder;

    @Before
    public void setUp() {
        mEapAkaTypeDataDecoder = EapAkaTypeData.getEapAkaTypeDataDecoder();
    }

    @Test
    public void testDecode() {
        DecodeResult<EapAkaTypeData> result =
                mEapAkaTypeDataDecoder.decode(EAP_AKA_CHALLENGE_RESPONSE_TYPE_DATA);

        assertTrue(result.isSuccessfulDecode());
        EapAkaTypeData eapAkaTypeData = result.eapTypeData;
        assertEquals(EAP_AKA_CHALLENGE, eapAkaTypeData.eapSubtype);

        // also check Map entries (needs to match input order)
        Iterator<Entry<Integer, EapSimAkaAttribute>> itr =
                eapAkaTypeData.attributeMap.entrySet().iterator();
        Entry<Integer, EapSimAkaAttribute> entry = itr.next();
        assertEquals(EAP_AT_RES, (int) entry.getKey());
        assertArrayEquals(RES_BYTES, ((AtRes) entry.getValue()).res);

        entry = itr.next();
        assertEquals(EAP_AT_MAC, (int) entry.getKey());
        assertArrayEquals(EAP_AKA_CHALLENGE_RESPONSE_MAC_BYTES, ((AtMac) entry.getValue()).mac);

        assertFalse(itr.hasNext());
    }

    @Test
    public void testDecodeInvalidSubtype() {
        DecodeResult<EapAkaTypeData> result = mEapAkaTypeDataDecoder.decode(INVALID_SUBTYPE);
        assertFalse(result.isSuccessfulDecode());
        assertEquals(UNABLE_TO_PROCESS_CODE, result.atClientErrorCode.errorCode);
    }

    @Test
    public void testEncode() throws Exception {
        LinkedHashMap<Integer, EapSimAkaAttribute> attributes = new LinkedHashMap<>();
        attributes.put(EAP_AT_ANY_ID_REQ, new AtAnyIdReq());
        EapAkaTypeData eapAkaTypeData = new EapAkaTypeData(EAP_AKA_IDENTITY, attributes);

        byte[] result = eapAkaTypeData.encode();
        assertArrayEquals(EAP_AKA_IDENTITY_REQUEST, result);
    }
}
