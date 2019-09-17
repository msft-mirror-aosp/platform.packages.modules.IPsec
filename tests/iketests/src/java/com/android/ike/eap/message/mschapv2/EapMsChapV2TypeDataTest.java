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

package com.android.ike.eap.message.mschapv2;

import static com.android.ike.eap.message.mschapv2.EapMsChapV2TypeData.EAP_MSCHAP_V2_CHALLENGE;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.exceptions.mschapv2.EapMsChapV2ParsingException;
import com.android.ike.eap.message.mschapv2.EapMsChapV2TypeData.EapMsChapV2TypeDataDecoder.DecodeResult;
import com.android.ike.eap.message.mschapv2.EapMsChapV2TypeData.EapMsChapV2VariableTypeData;

import org.junit.Test;

public class EapMsChapV2TypeDataTest {
    private static final int INVALID_OPCODE = -1;
    private static final int MSCHAP_V2_ID = 1;
    private static final int MS_LENGTH = 32;

    @Test
    public void testEapMsChapV2TypeDataConstructor() throws Exception {
        EapMsChapV2TypeData typeData = new EapMsChapV2TypeData(EAP_MSCHAP_V2_CHALLENGE) {};
        assertEquals(EAP_MSCHAP_V2_CHALLENGE, typeData.opCode);

        try {
            new EapMsChapV2TypeData(INVALID_OPCODE) {};
            fail("ExpectedEapMsChapV2ParsingException for invalid OpCode");
        } catch (EapMsChapV2ParsingException expected) {
        }
    }

    @Test
    public void testEapMsChapV2VariableTypeDataConstructor() throws Exception {
        EapMsChapV2VariableTypeData typeData =
                new EapMsChapV2VariableTypeData(
                        EAP_MSCHAP_V2_CHALLENGE, MSCHAP_V2_ID, MS_LENGTH) {};
        assertEquals(EAP_MSCHAP_V2_CHALLENGE, typeData.opCode);
        assertEquals(MSCHAP_V2_ID, typeData.msChapV2Id);
        assertEquals(MS_LENGTH, typeData.msLength);

        try {
            new EapMsChapV2VariableTypeData(INVALID_OPCODE, MSCHAP_V2_ID, MS_LENGTH) {};
            fail("ExpectedEapMsChapV2ParsingException for invalid OpCode");
        } catch (EapMsChapV2ParsingException expected) {
        }
    }

    @Test
    public void testDecodeResultIsSuccessfulDecode() throws Exception {
        DecodeResult<EapMsChapV2TypeData> result =
                new DecodeResult(new EapMsChapV2TypeData(EAP_MSCHAP_V2_CHALLENGE) {});
        assertTrue(result.isSuccessfulDecode());

        result = new DecodeResult(new EapError(new Exception()));
        assertFalse(result.isSuccessfulDecode());
    }
}
