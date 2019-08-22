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

import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_IDENTITY_REQUEST;
import static com.android.ike.eap.message.EapTestMessageDefinitions.INVALID_SUBTYPE;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_IDENTITY;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_ANY_ID_REQ;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import com.android.ike.eap.message.simaka.EapAkaTypeData.EapAkaTypeDataDecoder;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtAnyIdReq;

import org.junit.Before;
import org.junit.Test;

import java.util.LinkedHashMap;

public class EapAkaTypeDataTest {
    private static final int UNABLE_TO_PROCESS_CODE = 0;

    private EapAkaTypeDataDecoder mEapAkaTypeDataDecoder;

    @Before
    public void setUp() {
        mEapAkaTypeDataDecoder = EapAkaTypeData.getEapAkaTypeDataDecoder();
    }

    @Test
    public void testDecode() {

    }

    @Test
    public void testDecodeInvalidSubtype() {
        EapSimAkaTypeData.DecodeResult<EapAkaTypeData> result =
                mEapAkaTypeDataDecoder.decode(INVALID_SUBTYPE);
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
