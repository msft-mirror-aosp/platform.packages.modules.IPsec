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

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.TestUtils.hexStringToInt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapInvalidPacketLengthException;
import com.android.ike.eap.exceptions.InvalidEapCodeException;

import org.junit.Test;

public class EapMessageTest {
    private static final String REQUEST_CODE = "01";
    private static final String SUCCESS_CODE = "03";
    private static final String IDENTIFIER = "10";
    private static final String REQUEST_LENGTH = "000A";
    private static final String SUCCESS_LENGTH = "0004";

    private static final String INVALID_CODE = "F0";
    private static final String INVALID_LENGTH = "0005";

    private static final String SUCCESS_PACKET = SUCCESS_CODE + IDENTIFIER + SUCCESS_LENGTH;
    private static final String INVALID_CODE_PACKET = INVALID_CODE + IDENTIFIER + SUCCESS_LENGTH;
    private static final String SHORT_HEADER = SUCCESS_CODE + IDENTIFIER;
    private static final String SHORT_PACKET = SUCCESS_CODE + IDENTIFIER + INVALID_LENGTH;
    private static final String SUCCESS_PACKET_TOO_LONG =
            SUCCESS_CODE + IDENTIFIER + INVALID_LENGTH + "00";

    private static final String MISSING_TYPE_LENGTH = "0004";
    private static final String AKA_TYPE = "17"; // 0x17 = 23
    private static final String AKA_IDENTITY_SUBTYPE = "05";
    private static final String AKA_AT_PERMANENT_ID_REQ_ATTRIBUTE = "0C010000";

    private static final String REQUEST_PACKET =
            REQUEST_CODE
            + IDENTIFIER
            + REQUEST_LENGTH
            + AKA_TYPE
            + AKA_IDENTITY_SUBTYPE
            + AKA_AT_PERMANENT_ID_REQ_ATTRIBUTE;
    private static final String MISSING_TYPE_PACKET =
            REQUEST_CODE
            + IDENTIFIER
            + MISSING_TYPE_LENGTH;

    @Test
    public void testDecode() throws Exception {
        EapMessage result = EapMessage.decode(hexStringToByteArray(SUCCESS_PACKET));

        assertEquals(hexStringToInt(SUCCESS_CODE), result.eapCode);
        assertEquals(hexStringToInt(IDENTIFIER), result.eapIdentifier);
        assertEquals(hexStringToInt(SUCCESS_LENGTH), result.eapLength);
        assertNull(result.eapData);

        EapData expectedEapData = new EapData(EapData.EAP_TYPE_AKA,
                hexStringToByteArray(AKA_IDENTITY_SUBTYPE + AKA_AT_PERMANENT_ID_REQ_ATTRIBUTE));
        result = EapMessage.decode(hexStringToByteArray(REQUEST_PACKET));
        assertEquals(hexStringToInt(REQUEST_CODE), result.eapCode);
        assertEquals(hexStringToInt(IDENTIFIER), result.eapIdentifier);
        assertEquals(hexStringToInt(REQUEST_LENGTH), result.eapLength);
        assertEquals(expectedEapData, result.eapData);
    }

    @Test
    public void testDecodeInvalidCode() throws Exception {
        try {
            EapMessage.decode(hexStringToByteArray(INVALID_CODE_PACKET));
            fail("Expected InvalidEapCodeException");
        } catch (InvalidEapCodeException expected) {
        }
    }

    @Test
    public void testDecodeShortHeader() throws Exception {
        try {
            EapMessage.decode(hexStringToByteArray(SHORT_HEADER));
            fail("Expected EapInvalidPacketLengthException");
        } catch (EapInvalidPacketLengthException expected) {
        }
    }

    @Test
    public void testDecodeShortPacket() throws Exception {
        try {
            EapMessage.decode(hexStringToByteArray(SHORT_PACKET));
            fail("Expected EapInvalidPacketLengthException");
        } catch (EapInvalidPacketLengthException expected) {
        }
    }

    @Test
    public void testDecodeSuccessIncorrectLength() throws Exception {
        try {
            EapMessage.decode(hexStringToByteArray(SUCCESS_PACKET_TOO_LONG));
            fail("Expected EapInvalidPacketLengthException");
        } catch (EapInvalidPacketLengthException expected) {
        }
    }

    @Test
    public void testDecodeMissingTypeData() throws Exception {
        try {
            EapMessage.decode(hexStringToByteArray(MISSING_TYPE_PACKET));
            fail("Expected EapInvalidPacketLengthException");
        } catch (EapInvalidPacketLengthException expected) {
        }
    }

    @Test
    public void testEncode() throws Exception {
        // TODO(b/133248540): fully test EapMessage#encode functionality
        byte[] expectedPacket = hexStringToByteArray(SUCCESS_PACKET);
        EapMessage eapMessage = EapMessage.decode(expectedPacket);

        byte[] actualPacket = eapMessage.encode();
        assertEquals(expectedPacket.length, actualPacket.length);
    }
}
