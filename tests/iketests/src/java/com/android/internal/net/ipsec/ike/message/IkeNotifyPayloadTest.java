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

package com.android.internal.net.ipsec.ike.message;

import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_AUTHENTICATION_FAILED;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_INTERNAL_ADDRESS_FAILURE;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_IKE_SPI;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_KE_PAYLOAD;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_SYNTAX;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_NO_ADDITIONAL_SAS;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_NO_PROPOSAL_CHOSEN;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_SINGLE_PAIR_REQUIRED;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_TS_UNACCEPTABLE;
import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.net.ipsec.ike.SaProposal;
import android.net.ipsec.ike.exceptions.IkeProtocolException;
import android.net.ipsec.ike.exceptions.protocol.AuthenticationFailedException;
import android.net.ipsec.ike.exceptions.protocol.InternalAddressFailureException;
import android.net.ipsec.ike.exceptions.protocol.InvalidIkeSpiException;
import android.net.ipsec.ike.exceptions.protocol.InvalidKeException;
import android.net.ipsec.ike.exceptions.protocol.InvalidSyntaxException;
import android.net.ipsec.ike.exceptions.protocol.NoAdditionalSasException;
import android.net.ipsec.ike.exceptions.protocol.NoValidProposalChosenException;
import android.net.ipsec.ike.exceptions.protocol.SinglePairRequiredException;
import android.net.ipsec.ike.exceptions.protocol.TemporaryFailureException;
import android.net.ipsec.ike.exceptions.protocol.TsUnacceptableException;
import android.net.ipsec.ike.exceptions.protocol.UnrecognizedIkeProtocolException;

import com.android.internal.net.TestUtils;

import org.junit.Test;

import java.net.InetAddress;
import java.nio.ByteBuffer;

public final class IkeNotifyPayloadTest {
    private static final String NOTIFY_NAT_DETECTION_PAYLOAD_HEX_STRING =
            "2900001c00004004e54f73b7d83f6beb881eab2051d8663f421d10b0";
    private static final String NOTIFY_NAT_DETECTION_PAYLOAD_BODY_HEX_STRING =
            "00004004e54f73b7d83f6beb881eab2051d8663f421d10b0";
    private static final String NAT_DETECTION_DATA_HEX_STRING =
            "e54f73b7d83f6beb881eab2051d8663f421d10b0";

    private static final String NOTIFY_REKEY_PAYLOAD_BODY_HEX_STRING = "030440092ad4c0a2";
    private static final int REKEY_SPI = 0x2ad4c0a2;

    private static final String IKE_INITIATOR_SPI_HEX_STRING = "5f54bf6d8b48e6e1";
    private static final String IKE_RESPODNER_SPI_HEX_STRING = "0000000000000000";
    private static final String IP_ADDR = "10.80.80.13";
    private static final int PORT = 500;

    private static final int PROTOCOL_ID_OFFSET = 0;

    @Test
    public void testDecodeNotifyPayloadSpiUnset() throws Exception {
        byte[] inputPacket =
                TestUtils.hexStringToByteArray(NOTIFY_NAT_DETECTION_PAYLOAD_BODY_HEX_STRING);
        byte[] notifyData = TestUtils.hexStringToByteArray(NAT_DETECTION_DATA_HEX_STRING);

        IkeNotifyPayload payload = new IkeNotifyPayload(false, inputPacket);
        assertEquals(IkePayload.PROTOCOL_ID_UNSET, payload.protocolId);
        assertEquals(IkePayload.SPI_LEN_NOT_INCLUDED, payload.spiSize);
        assertEquals(IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP, payload.notifyType);
        assertEquals(IkePayload.SPI_NOT_INCLUDED, payload.spi);
        assertArrayEquals(notifyData, payload.notifyData);
    }

    @Test
    public void testDecodeNotifyPayloadSpiSet() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(NOTIFY_REKEY_PAYLOAD_BODY_HEX_STRING);

        IkeNotifyPayload payload = new IkeNotifyPayload(false, inputPacket);
        assertEquals(IkePayload.PROTOCOL_ID_ESP, payload.protocolId);
        assertEquals(IkePayload.SPI_LEN_IPSEC, payload.spiSize);
        assertEquals(IkeNotifyPayload.NOTIFY_TYPE_REKEY_SA, payload.notifyType);
        assertEquals(REKEY_SPI, payload.spi);
        assertArrayEquals(new byte[0], payload.notifyData);
    }

    @Test
    public void testGenerateNatDetectionData() throws Exception {
        long initiatorIkeSpi = Long.parseLong(IKE_INITIATOR_SPI_HEX_STRING, 16);
        long responderIkespi = Long.parseLong(IKE_RESPODNER_SPI_HEX_STRING, 16);
        InetAddress inetAddress = InetAddress.getByName(IP_ADDR);

        byte[] netDetectionData =
                IkeNotifyPayload.generateNatDetectionData(
                        initiatorIkeSpi, responderIkespi, inetAddress, PORT);

        byte[] expectedBytes = TestUtils.hexStringToByteArray(NAT_DETECTION_DATA_HEX_STRING);
        assertArrayEquals(expectedBytes, netDetectionData);
    }

    @Test
    public void testBuildIkeErrorNotifyWithData() throws Exception {
        int payloadType = 1;
        IkeNotifyPayload notifyPayload =
                new IkeNotifyPayload(
                        IkeProtocolException.ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD,
                        new byte[] {(byte) payloadType});

        assertArrayEquals(new byte[] {(byte) payloadType}, notifyPayload.notifyData);
        assertTrue(notifyPayload.isErrorNotify());
        assertFalse(notifyPayload.isNewChildSaNotify());
    }

    @Test
    public void testBuildIkeErrorNotifyWithoutData() throws Exception {
        IkeNotifyPayload notifyPayload =
                new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_INVALID_SYNTAX);

        assertArrayEquals(new byte[0], notifyPayload.notifyData);
        assertTrue(notifyPayload.isErrorNotify());
        assertFalse(notifyPayload.isNewChildSaNotify());
    }

    @Test
    public void testBuildChildConfigNotify() throws Exception {
        IkeNotifyPayload notifyPayload =
                new IkeNotifyPayload(IkeNotifyPayload.NOTIFY_TYPE_USE_TRANSPORT_MODE);

        assertArrayEquals(new byte[0], notifyPayload.notifyData);
        assertFalse(notifyPayload.isErrorNotify());
        assertTrue(notifyPayload.isNewChildSaNotify());
    }

    @Test
    public void testBuildChildErrorNotify() throws Exception {
        IkeNotifyPayload notifyPayload =
                new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_INTERNAL_ADDRESS_FAILURE);

        assertArrayEquals(new byte[0], notifyPayload.notifyData);
        assertTrue(notifyPayload.isErrorNotify());
        assertTrue(notifyPayload.isNewChildSaNotify());
    }

    @Test
    public void testEncodeNotifyPayload() throws Exception {
        byte[] inputPacket =
                TestUtils.hexStringToByteArray(NOTIFY_NAT_DETECTION_PAYLOAD_BODY_HEX_STRING);
        IkeNotifyPayload payload = new IkeNotifyPayload(false, inputPacket);

        ByteBuffer byteBuffer = ByteBuffer.allocate(payload.getPayloadLength());
        payload.encodeToByteBuffer(IkePayload.PAYLOAD_TYPE_NOTIFY, byteBuffer);

        byte[] expectedNoncePayload =
                TestUtils.hexStringToByteArray(NOTIFY_NAT_DETECTION_PAYLOAD_HEX_STRING);
        assertArrayEquals(expectedNoncePayload, byteBuffer.array());
    }

    @Test
    public void testValidateAndBuildIkeExceptionWithData() throws Exception {
        // Invalid Message ID
        byte[] dhGroup = new byte[] {(byte) 0x00, (byte) 0x0e};
        int expectedDhGroup = SaProposal.DH_GROUP_2048_BIT_MODP;

        IkeNotifyPayload payload = new IkeNotifyPayload(ERROR_TYPE_INVALID_KE_PAYLOAD, dhGroup);
        IkeProtocolException exception = payload.validateAndBuildIkeException();

        assertTrue(exception instanceof InvalidKeException);
        assertEquals(ERROR_TYPE_INVALID_KE_PAYLOAD, exception.getErrorType());
        assertArrayEquals(dhGroup, exception.getErrorData());
        assertEquals(expectedDhGroup, ((InvalidKeException) exception).getDhGroup());
    }

    private <T extends IkeProtocolException> void verifyValidateAndBuildIkeExceptionWithoutData(
            int errorType, Class<T> exceptionClass) throws Exception {
        IkeNotifyPayload payload = new IkeNotifyPayload(errorType);
        IkeProtocolException exception = payload.validateAndBuildIkeException();

        assertTrue(exceptionClass.isInstance(exception));
        assertEquals(errorType, exception.getErrorType());
        assertArrayEquals(new byte[0], exception.getErrorData());
    }

    @Test
    public void testValidateAndBuildAuthFailException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_AUTHENTICATION_FAILED, AuthenticationFailedException.class);
    }

    @Test
    public void testValidateAndBuildInvalidIkeSpiException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_INVALID_IKE_SPI, InvalidIkeSpiException.class);
    }

    @Test
    public void testValidateAndBuildInvalidSyntaxException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_INVALID_SYNTAX, InvalidSyntaxException.class);
    }

    @Test
    public void testValidateAndBuildNoProposalChosenException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_NO_PROPOSAL_CHOSEN, NoValidProposalChosenException.class);
    }

    @Test
    public void testValidateAndBuildSinglePairRequiredException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_SINGLE_PAIR_REQUIRED, SinglePairRequiredException.class);
    }

    @Test
    public void testValidateAndBuildNoAdditionalSasException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_NO_ADDITIONAL_SAS, NoAdditionalSasException.class);
    }

    @Test
    public void testValidateAndBuildInternalAddressFailException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_INTERNAL_ADDRESS_FAILURE, InternalAddressFailureException.class);
    }

    @Test
    public void testValidateAndBuildTsUnacceptableException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_TS_UNACCEPTABLE, TsUnacceptableException.class);
    }

    @Test
    public void testValidateAndBuildTemporaryFailureException() throws Exception {
        verifyValidateAndBuildIkeExceptionWithoutData(
                ERROR_TYPE_TEMPORARY_FAILURE, TemporaryFailureException.class);
    }

    @Test
    public void testValidateAndBuildUnrecognizedIkeException() throws Exception {
        int unrecognizedType = 0;
        IkeNotifyPayload payload = new IkeNotifyPayload(unrecognizedType);
        IkeProtocolException exception = payload.validateAndBuildIkeException();

        assertTrue(exception instanceof UnrecognizedIkeProtocolException);
        assertEquals(unrecognizedType, exception.getErrorType());
        assertArrayEquals(new byte[0], exception.getErrorData());
    }

    @Test
    public void testValidateAndBuildIkeExceptionWithInvalidPayload() throws Exception {
        // Build a invalid notify payload
        IkeNotifyPayload payload = new IkeNotifyPayload(ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD);

        try {
            payload.validateAndBuildIkeException();
            fail("Expected to fail due to invalid error data");
        } catch (InvalidSyntaxException expected) {
        }
    }

    @Test
    public void testBuildIkeExceptionWithStatusNotify() throws Exception {
        // Rekey notification
        byte[] inputPacket = TestUtils.hexStringToByteArray(NOTIFY_REKEY_PAYLOAD_BODY_HEX_STRING);
        IkeNotifyPayload payload = new IkeNotifyPayload(false, inputPacket);

        assertFalse(payload.isErrorNotify());

        try {
            payload.validateAndBuildIkeException();
            fail("Expected to fail because it is not error notification");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testGetNotifyTypeString() throws Exception {
        IkeNotifyPayload payload = new IkeNotifyPayload(ERROR_TYPE_AUTHENTICATION_FAILED);

        assertEquals("Notify(Authentication failed)", payload.getTypeString());
    }

    @Test
    public void testGetNotifyTypeStringForUnrecoginizedNotify() throws Exception {
        int unrecognizedType = 0;
        IkeNotifyPayload payload = new IkeNotifyPayload(unrecognizedType);

        assertEquals("Notify(0)", payload.getTypeString());
    }
}
