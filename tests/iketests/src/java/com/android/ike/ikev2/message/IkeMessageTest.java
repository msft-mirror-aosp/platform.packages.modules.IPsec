/*
 * Copyright (C) 2018 The Android Open Source Project
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

package com.android.ike.ikev2.message;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.ikev2.exceptions.InvalidMajorVersionException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.exceptions.UnsupportedCriticalPayloadException;

import org.junit.Test;

public final class IkeMessageTest {
    private static final String IKE_SA_INIT_RAW_PACKET =
            "8f54bf6d8b48e6e100000000000000002120220800000000"
                    + "00000150220000300000002c010100040300000c0100000c"
                    + "800e00800300000803000002030000080400000200000008"
                    + "020000022800008800020000b4a2faf4bb54878ae21d6385"
                    + "12ece55d9236fc5046ab6cef82220f421f3ce6361faf3656"
                    + "4ecb6d28798a94aad7b2b4b603ddeaaa5630adb9ece8ac37"
                    + "534036040610ebdd92f46bef84f0be7db860351843858f8a"
                    + "cf87056e272377f70c9f2d81e29c7b0ce4f291a3a72476bb"
                    + "0b278fd4b7b0a4c26bbeb08214c707137607958729000024"
                    + "c39b7f368f4681b89fa9b7be6465abd7c5f68b6ed5d3b4c7"
                    + "2cb4240eb5c464122900001c00004004e54f73b7d83f6beb"
                    + "881eab2051d8663f421d10b02b00001c00004005d915368c"
                    + "a036004cb578ae3e3fb268509aeab1900000002069936922"
                    + "8741c6d4ca094c93e242c9de19e7b7c60000000500000500";
    private static final String IKE_INITIATOR_SPI = "8f54bf6d8b48e6e1";
    private static final String IKE_RESPODNER_SPI = "0000000000000000";

    @IkePayload.PayloadType
    private static final byte IKE_FIRST_PAYLOAD_TYPE = IkePayload.PAYLOAD_TYPE_SA;

    private static final byte IKE_MAJOR_VERSION = 2;
    private static final byte IKE_MINOR_VERSION = 0;

    @IkeHeader.ExchangeType
    private static final int IKE_EXCHANGE_TYPE = IkeHeader.EXCHANGE_TYPE_IKE_INIT_SA;

    private static final int IKE_MSG_ID = 0;
    private static final int IKE_MSG_LENGTH = 336;

    private static final int FIRST_PAYLOAD_TYPE_POSITION = 16;
    private static final int VERSION_POSITION = 17;
    private static final int EXCHANGE_TYPE_POSITION = 18;
    private static final int PAYLOAD_CRITICAL_BIT_POSITION = 1;

    private static final int PAYLOAD_NUMBER = 0;

    @Test
    public void testDecodeIkeHeader() throws Exception {
        byte[] inputPacket = hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        IkeHeader header = new IkeHeader(inputPacket);

        assertEquals(IKE_MSG_LENGTH, inputPacket.length);

        long initSpi = Long.parseUnsignedLong(IKE_INITIATOR_SPI, 16);
        assertEquals(initSpi, header.ikeInitiatorSpi);
        long respSpi = Long.parseUnsignedLong(IKE_RESPODNER_SPI, 16);
        assertEquals(respSpi, header.ikeResponderSpi);

        assertEquals(IKE_FIRST_PAYLOAD_TYPE, header.nextPayloadType);
        assertEquals(IKE_MAJOR_VERSION, header.majorVersion);
        assertEquals(IKE_MINOR_VERSION, header.minorVersion);
        assertEquals(IKE_EXCHANGE_TYPE, header.exchangeType);
        assertFalse(header.isResponse);
        assertTrue(header.fromIkeInitiator);
        assertEquals(IKE_MSG_ID, header.messageId);
        assertEquals(IKE_MSG_LENGTH, header.messageLength);
    }

    @Test
    public void testDecodeIkePayload() throws Exception {
        byte[] inputPacket = hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        IkeHeader header = new IkeHeader(inputPacket);
        IkeMessage message = IkeMessage.decode(header, inputPacket);
        assertEquals(PAYLOAD_NUMBER, message.ikePayloadList.size());
    }

    @Test
    public void testThrowInvalidMajorVersionException() throws Exception {
        byte[] inputPacket = hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Set major version 3.
        inputPacket[VERSION_POSITION] = (byte) 0x30;
        // Set Exchange type 0
        inputPacket[EXCHANGE_TYPE_POSITION] = (byte) 0x00;
        IkeHeader header = new IkeHeader(inputPacket);
        try {
            IkeMessage.decode(header, inputPacket);
            fail(
                    "Expected InvalidMajorVersionException: major version is 3"
                            + "and packet length is 0");
        } catch (InvalidMajorVersionException expected) {
            assertEquals(3, expected.receivedMajorVersion);
        }
    }

    @Test
    public void testThrowInvalidSyntaxException() throws Exception {
        byte[] inputPacket = hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Set Exchange type 0
        inputPacket[EXCHANGE_TYPE_POSITION] = (byte) 0x00;
        IkeHeader header = new IkeHeader(inputPacket);
        try {
            IkeMessage.decode(header, inputPacket);
            fail("Expected InvalidSyntaxException: packet length is 0");
        } catch (InvalidSyntaxException expected) {
        }
    }

    @Test
    public void testThrowUnsupportedCriticalPayloadException() throws Exception {
        byte[] inputPacket = hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Set first payload unsupported critical
        inputPacket[FIRST_PAYLOAD_TYPE_POSITION] = (byte) 0xff;
        inputPacket[IkeHeader.IKE_HEADER_LENGTH + PAYLOAD_CRITICAL_BIT_POSITION] = (byte) 0x80;

        IkeHeader header = new IkeHeader(inputPacket);
        try {
            IkeMessage.decode(header, inputPacket);
            fail(
                    "Expected UnsupportedCriticalPayloadException: first"
                            + "payload is unsupported critical.");
        } catch (UnsupportedCriticalPayloadException expected) {
            assertEquals(1, expected.payloadTypeList.size());
        }
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
