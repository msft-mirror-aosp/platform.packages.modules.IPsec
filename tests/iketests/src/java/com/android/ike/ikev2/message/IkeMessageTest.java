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

import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_OK;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_PROTECTED_ERROR;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_UNPROTECTED_ERROR;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_AUTH;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_ID_INITIATOR;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NO_NEXT;
import static com.android.ike.ikev2.message.IkeTestUtils.makeDummySkfPayload;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.IkeInternalException;
import com.android.ike.ikev2.exceptions.InvalidMessageIdException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.exceptions.UnsupportedCriticalPayloadException;
import com.android.ike.ikev2.message.IkeMessage.DecodeResult;
import com.android.ike.ikev2.message.IkeMessage.DecodeResultError;
import com.android.ike.ikev2.message.IkeMessage.DecodeResultOk;
import com.android.ike.ikev2.message.IkeMessage.DecodeResultPartial;
import com.android.ike.ikev2.message.IkePayloadFactory.IIkePayloadDecoder;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedList;

import javax.crypto.IllegalBlockSizeException;

public final class IkeMessageTest {
    private static final String IKE_SA_INIT_HEADER_RAW_PACKET =
            "8f54bf6d8b48e6e10000000000000000212022080000000000000150";
    private static final String IKE_SA_INIT_BODY_RAW_PACKET =
            "220000300000002c010100040300000c0100000c"
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
    private static final String IKE_SA_INIT_RAW_PACKET =
            IKE_SA_INIT_HEADER_RAW_PACKET + IKE_SA_INIT_BODY_RAW_PACKET;

    // Byte offsets of first payload type in IKE message header.
    private static final int FIRST_PAYLOAD_TYPE_OFFSET = 16;
    // Byte offsets of first payload's critical bit in IKE message body.
    private static final int PAYLOAD_CRITICAL_BIT_OFFSET = 1;
    // Byte offsets of first payload length in IKE message body.
    private static final int FIRST_PAYLOAD_LENGTH_OFFSET = 2;
    // Byte offsets of last payload length in IKE message body.
    private static final int LAST_PAYLOAD_LENGTH_OFFSET = 278;

    private static final String IKE_AUTH_HEADER_HEX_STRING =
            "5f54bf6d8b48e6e1909232b3d1edcb5c2e20230800000001000000ec";
    private static final String IKE_AUTH_BODY_HEX_STRING =
            "230000d0b9132b7bb9f658dfdc648e5017a6322a030c316c"
                    + "e55f365760d46426ce5cfc78bd1ed9abff63eb9594c1bd58"
                    + "46de333ecd3ea2b705d18293b130395300ba92a351041345"
                    + "0a10525cea51b2753b4e92b081fd78d995659a98f742278f"
                    + "f9b8fd3e21554865c15c79a5134d66b2744966089e416c60"
                    + "a274e44a9a3f084eb02f3bdce1e7de9de8d9a62773ab563b"
                    + "9a69ba1db03c752acb6136452b8a86c41addb4210d68c423"
                    + "efed80e26edca5fa3fe5d0a5ca9375ce332c474b93fb1fa3"
                    + "59eb4e81ae6e0f22abdad69ba8007d50";

    private static final String IKE_AUTH_EXPECTED_CHECKSUM_HEX_STRING = "ae6e0f22abdad69ba8007d50";
    private static final String IKE_AUTH_HEX_STRING =
            IKE_AUTH_HEADER_HEX_STRING + IKE_AUTH_BODY_HEX_STRING;

    private static final String IKE_AUTH_UNENCRYPTED_PADDED_DATA_HEX_STRING =
            "2400000c010000000a50500d2700000c010000000a505050"
                    + "2100001c02000000df7c038aefaaa32d3f44b228b52a3327"
                    + "44dfb2c12c00002c00000028010304032ad4c0a20300000c"
                    + "0100000c800e008003000008030000020000000805000000"
                    + "2d00001801000000070000100000ffff00000000ffffffff"
                    + "2900001801000000070000100000ffff00000000ffffffff"
                    + "29000008000040000000000c000040010000000100000000"
                    + "000000000000000b";

    private static final String IKE_FRAG_HEX_STRING =
            "939ae1251d18eb9077a99551b15c6e9335202320000000010000"
                    + "00c0000000a400020002fd7c7931705af184b7be76bbd45a"
                    + "8ecbb3ffd58b9438b93f67e9fe86b06229f80e9b52d2ff6a"
                    + "fde3f2c13ae93ce55a801f62e1a818c9003880a36bbe986f"
                    + "e6979ba233b9f4f0ddc992d06dbad5a2b998be18fae947e5"
                    + "ccfb37775d069344e711fbf499bb289cf4cca245bd450ad8"
                    + "9d18689207759507ba18d47247e920b9e000a25a7596e413"
                    + "0929e5cdc37d5c1b0d90bbaae946c260f4d3cf815f6d";
    private static final String ID_INIT_PAYLOAD_HEX_STRING = "2400000c010000000a50500d";
    private static final String ID_RESP_PAYLOAD_HEX_STRING = "0000000c010000000a505050";

    private static final long INIT_SPI = 0x5f54bf6d8b48e6e1L;
    private static final long RESP_SPI = 0x909232b3d1edcb5cL;
    private static final String IKE_EMPTY_INFO_MSG_HEX_STRING =
            "5f54bf6d8b48e6e1909232b3d1edcb5c2e20252800000000"
                    + "0000004c00000030e376871750fdba9f7012446c5dc3f97a"
                    + "f83b48ba0dbc68bcc4a78136832100aa4192f251cd4d1b97"
                    + "d298e550";
    private static final String IKE_EMPTY_INFO_MSG_IV_HEX_STRING =
            "e376871750fdba9f7012446c5dc3f97a";
    private static final String IKE_EMPTY_INFO_MSG_ENCRYPTED_DATA_HEX_STRING =
            "f83b48ba0dbc68bcc4a78136832100aa";
    private static final String IKE_EMPTY_INFO_MSG_CHECKSUM_HEX_STRING = "4192f251cd4d1b97d298e550";

    private static final byte[] FRAGMENT_ONE_UNENCRYPTED_DATA = "fragmentOne".getBytes();
    private static final byte[] FRAGMENT_TWO_UNENCRYPTED_DATA = "fragmentTwo".getBytes();

    private static final int TOTAL_FRAGMENTS = 2;
    private static final int FRAGMENT_NUM_ONE = 1;
    private static final int FRAGMENT_NUM_TWO = 2;

    private static final int IKE_FRAG_EXPECTED_MESSAGE_ID = 1;
    private static final int TOTAL_FRAGMENTS_OFFSET =
            IkeHeader.IKE_HEADER_LENGTH + IkePayload.GENERIC_HEADER_LENGTH + 2;

    private static final int IKE_AUTH_EXPECTED_MESSAGE_ID = 1;
    private static final int IKE_AUTH_CIPHER_IV_SIZE = 16;
    private static final int IKE_AUTH_CIPHER_BLOCK_SIZE = 16;
    private static final int IKE_AUTH_PAYLOAD_SIZE = 8;

    private byte[] mIkeAuthPacket;
    private byte[] mUnencryptedPaddedData;
    private IkeHeader mIkeAuthHeader;

    private IIkePayloadDecoder mSpyIkePayloadDecoder;

    private IkeMacIntegrity mMockIntegrity;
    private IkeCipher mMockCipher;
    private IkeSaRecord mMockIkeSaRecord;

    private byte[] mIkeFragPacket;
    private IkeHeader mFragOneHeader;
    private IkeHeader mFragTwoHeader;

    private IkeSkfPayload mDummySkfPayloadOne;
    private IkeSkfPayload mDummySkfPayloadTwo;

    private static final int[] EXPECTED_IKE_INIT_PAYLOAD_LIST = {
        IkePayload.PAYLOAD_TYPE_SA,
        IkePayload.PAYLOAD_TYPE_KE,
        IkePayload.PAYLOAD_TYPE_NONCE,
        IkePayload.PAYLOAD_TYPE_NOTIFY,
        IkePayload.PAYLOAD_TYPE_NOTIFY,
        IkePayload.PAYLOAD_TYPE_VENDOR
    };

    class TestIkeSupportedPayload extends IkePayload {
        TestIkeSupportedPayload(int payload, boolean critical) {
            super(payload, critical);
        }

        @Override
        protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
            throw new UnsupportedOperationException(
                    "It is not supported to encode " + getTypeString());
        }

        @Override
        protected int getPayloadLength() {
            throw new UnsupportedOperationException(
                    "It is not supported to get payload length of " + getTypeString());
        }

        @Override
        public String getTypeString() {
            return "Test Payload";
        }
    }

    @Before
    public void setUp() throws Exception {
        mSpyIkePayloadDecoder = spy(new IkePayloadFactory.IkePayloadDecoder());
        doAnswer(
                (invocation) -> {
                    int payloadType = (int) invocation.getArguments()[0];
                    boolean isCritical = (boolean) invocation.getArguments()[1];
                    if (support(payloadType)) {
                        return new TestIkeSupportedPayload(payloadType, isCritical);
                    }
                    return new IkeUnsupportedPayload(payloadType, isCritical);
                })
                .when(mSpyIkePayloadDecoder)
                .decodeIkePayload(anyInt(), anyBoolean(), anyBoolean(), any());

        IkePayloadFactory.sDecoderInstance = mSpyIkePayloadDecoder;

        mIkeAuthPacket = TestUtils.hexStringToByteArray(IKE_AUTH_HEX_STRING);
        mUnencryptedPaddedData =
                TestUtils.hexStringToByteArray(IKE_AUTH_UNENCRYPTED_PADDED_DATA_HEX_STRING);
        mIkeAuthHeader = new IkeHeader(mIkeAuthPacket);

        mMockIntegrity = mock(IkeMacIntegrity.class);
        byte[] expectedChecksum =
                TestUtils.hexStringToByteArray(IKE_AUTH_EXPECTED_CHECKSUM_HEX_STRING);
        when(mMockIntegrity.generateChecksum(any(), any())).thenReturn(expectedChecksum);
        when(mMockIntegrity.getChecksumLen()).thenReturn(expectedChecksum.length);

        mMockCipher = mock(IkeCipher.class);
        when(mMockCipher.getIvLen()).thenReturn(IKE_AUTH_CIPHER_IV_SIZE);
        when(mMockCipher.getBlockSize()).thenReturn(IKE_AUTH_CIPHER_BLOCK_SIZE);
        when(mMockCipher.decrypt(any(), any(), any())).thenReturn(mUnencryptedPaddedData);

        mMockIkeSaRecord = mock(IkeSaRecord.class);
        when(mMockIkeSaRecord.getInboundDecryptionKey()).thenReturn(new byte[0]);
        when(mMockIkeSaRecord.getInboundIntegrityKey()).thenReturn(new byte[0]);

        mIkeFragPacket = TestUtils.hexStringToByteArray(IKE_FRAG_HEX_STRING);
        mFragOneHeader = new IkeHeader(mIkeFragPacket);
        mFragTwoHeader = new IkeHeader(mIkeFragPacket);

        mDummySkfPayloadOne =
                makeDummySkfPayload(
                        FRAGMENT_ONE_UNENCRYPTED_DATA, FRAGMENT_NUM_ONE, TOTAL_FRAGMENTS);
        mDummySkfPayloadTwo =
                makeDummySkfPayload(
                        FRAGMENT_TWO_UNENCRYPTED_DATA, FRAGMENT_NUM_TWO, TOTAL_FRAGMENTS);
    }

    @After
    public void tearDown() {
        IkePayloadFactory.sDecoderInstance = new IkePayloadFactory.IkePayloadDecoder();
    }

    private IkeMessage verifyDecodeResultOkAndGetMessage(DecodeResult decodeResult)
            throws Exception {
        assertEquals(DECODE_STATUS_OK, decodeResult.status);

        DecodeResultOk resultOk = (DecodeResultOk) decodeResult;
        assertNotNull(resultOk.ikeMessage);

        return resultOk.ikeMessage;
    }

    private IkeException verifyDecodeResultErrorAndGetIkeException(
            DecodeResult decodeResult, int decodeStatus) throws Exception {
        assertEquals(decodeStatus, decodeResult.status);

        DecodeResultError resultError = (DecodeResultError) decodeResult;
        assertNotNull(resultError.ikeException);

        return resultError.ikeException;
    }

    @Test
    public void testDecodeIkeMessage() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        IkeHeader header = new IkeHeader(inputPacket);

        DecodeResult decodeResult = IkeMessage.decode(0, header, inputPacket);

        IkeMessage message = verifyDecodeResultOkAndGetMessage(decodeResult);

        assertEquals(EXPECTED_IKE_INIT_PAYLOAD_LIST.length, message.ikePayloadList.size());
        for (int i = 0; i < EXPECTED_IKE_INIT_PAYLOAD_LIST.length; i++) {
            assertEquals(
                    EXPECTED_IKE_INIT_PAYLOAD_LIST[i], message.ikePayloadList.get(i).payloadType);
        }
    }

    @Test
    public void testDecodeMessageWithUnsupportedUncriticalPayload() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Set first payload unsupported uncritical
        inputPacket[FIRST_PAYLOAD_TYPE_OFFSET] = (byte) 0xff;
        IkeHeader header = new IkeHeader(inputPacket);

        DecodeResult decodeResult = IkeMessage.decode(0, header, inputPacket);

        IkeMessage message = verifyDecodeResultOkAndGetMessage(decodeResult);

        assertEquals(EXPECTED_IKE_INIT_PAYLOAD_LIST.length - 1, message.ikePayloadList.size());
        for (int i = 0; i < EXPECTED_IKE_INIT_PAYLOAD_LIST.length - 1; i++) {
            assertEquals(
                    EXPECTED_IKE_INIT_PAYLOAD_LIST[i + 1],
                    message.ikePayloadList.get(i).payloadType);
        }
    }

    @Test
    public void testThrowUnsupportedCriticalPayloadException() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Set first payload unsupported critical
        inputPacket[FIRST_PAYLOAD_TYPE_OFFSET] = (byte) 0xff;
        inputPacket[IkeHeader.IKE_HEADER_LENGTH + PAYLOAD_CRITICAL_BIT_OFFSET] = (byte) 0x80;

        UnsupportedCriticalPayloadException exception =
                IkeTestUtils.decodeAndVerifyUnprotectedErrorMsg(
                        inputPacket, UnsupportedCriticalPayloadException.class);

        assertEquals(1, exception.payloadTypeList.size());
    }

    @Test
    public void testDecodeMessageWithTooShortPayloadLength() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Set first payload length to 0
        inputPacket[IkeHeader.IKE_HEADER_LENGTH + FIRST_PAYLOAD_LENGTH_OFFSET] = (byte) 0;
        inputPacket[IkeHeader.IKE_HEADER_LENGTH + FIRST_PAYLOAD_LENGTH_OFFSET + 1] = (byte) 0;

        IkeTestUtils.decodeAndVerifyUnprotectedErrorMsg(inputPacket, InvalidSyntaxException.class);
    }

    @Test
    public void testDecodeMessageWithTooLongPayloadLength() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        // Increase last payload length by one byte
        inputPacket[IkeHeader.IKE_HEADER_LENGTH + LAST_PAYLOAD_LENGTH_OFFSET]++;

        IkeTestUtils.decodeAndVerifyUnprotectedErrorMsg(inputPacket, InvalidSyntaxException.class);
    }

    @Test
    public void testDecodeMessageWithUnexpectedBytesInTheEnd() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET + "0000");

        IkeTestUtils.decodeAndVerifyUnprotectedErrorMsg(inputPacket, InvalidSyntaxException.class);
    }

    @Test
    public void testDecodeEncryptedMessage() throws Exception {
        DecodeResult decodeResult =
                IkeMessage.decode(
                        IKE_AUTH_EXPECTED_MESSAGE_ID,
                        mMockIntegrity,
                        mMockCipher,
                        mMockIkeSaRecord,
                        mIkeAuthHeader,
                        mIkeAuthPacket,
                        null /*collectedFragments*/);
        IkeMessage ikeMessage = verifyDecodeResultOkAndGetMessage(decodeResult);

        assertEquals(IKE_AUTH_PAYLOAD_SIZE, ikeMessage.ikePayloadList.size());
    }

    @Test
    public void testDecodeEncryptedMessageWithWrongId() throws Exception {
        DecodeResult decodeResult =
                IkeMessage.decode(
                        2,
                        mMockIntegrity,
                        mMockCipher,
                        mMockIkeSaRecord,
                        mIkeAuthHeader,
                        mIkeAuthPacket,
                        null /*collectedFragments*/);
        IkeException ikeException =
                verifyDecodeResultErrorAndGetIkeException(
                        decodeResult, DECODE_STATUS_UNPROTECTED_ERROR);

        assertTrue(ikeException instanceof InvalidMessageIdException);
    }

    @Test
    public void testDecodeEncryptedMessageWithWrongChecksum() throws Exception {
        when(mMockIntegrity.generateChecksum(any(), any())).thenReturn(new byte[0]);

        DecodeResult decodeResult =
                IkeMessage.decode(
                        IKE_AUTH_EXPECTED_MESSAGE_ID,
                        mMockIntegrity,
                        mMockCipher,
                        mMockIkeSaRecord,
                        mIkeAuthHeader,
                        mIkeAuthPacket,
                        null /*collectedFragments*/);
        IkeException ikeException =
                verifyDecodeResultErrorAndGetIkeException(
                        decodeResult, DECODE_STATUS_UNPROTECTED_ERROR);

        assertTrue(
                ((IkeInternalException) ikeException).getCause()
                        instanceof GeneralSecurityException);
    }

    @Test
    public void testDecryptFail() throws Exception {
        when(mMockCipher.decrypt(any(), any(), any())).thenThrow(IllegalBlockSizeException.class);

        DecodeResult decodeResult =
                IkeMessage.decode(
                        IKE_AUTH_EXPECTED_MESSAGE_ID,
                        mMockIntegrity,
                        mMockCipher,
                        mMockIkeSaRecord,
                        mIkeAuthHeader,
                        mIkeAuthPacket,
                        null /*collectedFragments*/);

        IkeException ikeException =
                verifyDecodeResultErrorAndGetIkeException(
                        decodeResult, DECODE_STATUS_UNPROTECTED_ERROR);
        assertTrue(
                ((IkeInternalException) ikeException).getCause()
                        instanceof IllegalBlockSizeException);
    }

    @Test
    public void testParsingErrorInEncryptedMessage() throws Exception {
        // Set first payload length to 0
        byte[] decryptedData =
                Arrays.copyOfRange(mUnencryptedPaddedData, 0, mUnencryptedPaddedData.length);
        decryptedData[FIRST_PAYLOAD_LENGTH_OFFSET] = (byte) 0;
        decryptedData[FIRST_PAYLOAD_LENGTH_OFFSET + 1] = (byte) 0;
        when(mMockCipher.decrypt(any(), any(), any())).thenReturn(decryptedData);

        DecodeResult decodeResult =
                IkeMessage.decode(
                        IKE_AUTH_EXPECTED_MESSAGE_ID,
                        mMockIntegrity,
                        mMockCipher,
                        mMockIkeSaRecord,
                        mIkeAuthHeader,
                        mIkeAuthPacket,
                        null /*collectedFragments*/);
        IkeException ikeException =
                verifyDecodeResultErrorAndGetIkeException(
                        decodeResult, DECODE_STATUS_PROTECTED_ERROR);

        assertTrue(ikeException instanceof InvalidSyntaxException);
    }

    private boolean support(int payloadType) {
        // Supports all payload typs from 33 to 46
        return (payloadType >= 33 && payloadType <= 46);
    }

    @Test
    public void testAttachEncodedHeader() throws Exception {
        byte[] inputPacket = TestUtils.hexStringToByteArray(IKE_SA_INIT_RAW_PACKET);
        byte[] ikeBodyBytes = TestUtils.hexStringToByteArray(IKE_SA_INIT_BODY_RAW_PACKET);
        IkeHeader header = new IkeHeader(inputPacket);
        IkeMessage message =
                ((DecodeResultOk) IkeMessage.decode(0, header, inputPacket)).ikeMessage;

        byte[] encodedIkeMessage = message.attachEncodedHeader(ikeBodyBytes);
        assertArrayEquals(inputPacket, encodedIkeMessage);
    }

    @Test
    public void testEncodeAndEncryptEmptyMsg() throws Exception {
        when(mMockCipher.generateIv())
                .thenReturn(TestUtils.hexStringToByteArray(IKE_EMPTY_INFO_MSG_IV_HEX_STRING));
        when(mMockCipher.encrypt(any(), any(), any()))
                .thenReturn(
                        TestUtils.hexStringToByteArray(
                                IKE_EMPTY_INFO_MSG_ENCRYPTED_DATA_HEX_STRING));

        byte[] checkSum = TestUtils.hexStringToByteArray(IKE_EMPTY_INFO_MSG_CHECKSUM_HEX_STRING);
        when(mMockIntegrity.getChecksumLen()).thenReturn(checkSum.length);
        when(mMockIntegrity.generateChecksum(any(), any())).thenReturn(checkSum);

        IkeHeader ikeHeader =
                new IkeHeader(
                        INIT_SPI,
                        RESP_SPI,
                        IkePayload.PAYLOAD_TYPE_SK,
                        IkeHeader.EXCHANGE_TYPE_INFORMATIONAL,
                        true /*isResp*/,
                        true /*fromInit*/,
                        0);
        IkeMessage ikeMessage = new IkeMessage(ikeHeader, new LinkedList<>());

        byte[][] ikeMessageBytes =
                ikeMessage.encryptAndEncode(
                        mMockIntegrity,
                        mMockCipher,
                        mMockIkeSaRecord,
                        true /*supportFragment*/,
                        1280 /*fragSize*/);
        byte[][] expectedBytes =
                new byte[][] {TestUtils.hexStringToByteArray(IKE_EMPTY_INFO_MSG_HEX_STRING)};

        assertArrayEquals(expectedBytes, ikeMessageBytes);
    }

    private DecodeResultPartial makeDecodeResultForFragOne(DecodeResultPartial collectedFrags) {
        return new DecodeResultPartial(
                mFragOneHeader, mDummySkfPayloadOne, PAYLOAD_TYPE_AUTH, collectedFrags);
    }

    private DecodeResultPartial makeDecodeResultForFragTwo(DecodeResultPartial collectedFrags) {
        return new DecodeResultPartial(
                mFragTwoHeader, mDummySkfPayloadTwo, PAYLOAD_TYPE_NO_NEXT, collectedFrags);
    }

    @Test
    public void testConstructDecodePartialFirstFragArriveFirst() throws Exception {
        DecodeResultPartial resultPartial = makeDecodeResultForFragOne(null /*collectedFragments*/);

        assertEquals(mFragOneHeader, resultPartial.ikeHeader);

        assertEquals(TOTAL_FRAGMENTS, resultPartial.collectedFragsList.length);
        assertArrayEquals(
                FRAGMENT_ONE_UNENCRYPTED_DATA,
                resultPartial.collectedFragsList[FRAGMENT_NUM_ONE - 1]);
        assertFalse(resultPartial.isAllFragmentsReceived());
    }

    @Test
    public void testConstructDecodePartialSecondFragArriveFirst() throws Exception {
        DecodeResultPartial resultPartial = makeDecodeResultForFragTwo(null /*collectedFragments*/);

        assertEquals(PAYLOAD_TYPE_NO_NEXT, resultPartial.firstPayloadType);
        assertEquals(mFragTwoHeader, resultPartial.ikeHeader);

        assertEquals(TOTAL_FRAGMENTS, resultPartial.collectedFragsList.length);
        assertArrayEquals(
                FRAGMENT_TWO_UNENCRYPTED_DATA,
                resultPartial.collectedFragsList[FRAGMENT_NUM_TWO - 1]);
        assertFalse(resultPartial.isAllFragmentsReceived());
    }

    @Test
    public void testConstructDecodeResultPartialWithCollectedFrags() throws Exception {
        DecodeResultPartial resultPartialIncomplete =
                makeDecodeResultForFragTwo(null /*collectedFragments*/);
        DecodeResultPartial resultPartialComplete =
                makeDecodeResultForFragOne(resultPartialIncomplete);

        assertEquals(PAYLOAD_TYPE_AUTH, resultPartialComplete.firstPayloadType);
        assertEquals(mFragTwoHeader, resultPartialComplete.ikeHeader);

        assertEquals(TOTAL_FRAGMENTS, resultPartialComplete.collectedFragsList.length);
        assertTrue(resultPartialComplete.isAllFragmentsReceived());
    }

    @Test
    public void testReassembleAllFrags() throws Exception {
        DecodeResultPartial resultPartialIncomplete =
                makeDecodeResultForFragOne(null /*collectedFragments*/);
        DecodeResultPartial resultPartialComplete =
                makeDecodeResultForFragTwo(resultPartialIncomplete);

        assertEquals(PAYLOAD_TYPE_AUTH, resultPartialIncomplete.firstPayloadType);
        assertEquals(mFragOneHeader, resultPartialIncomplete.ikeHeader);

        assertEquals(TOTAL_FRAGMENTS, resultPartialIncomplete.collectedFragsList.length);
        assertTrue(resultPartialIncomplete.isAllFragmentsReceived());

        // Verify reassembly result
        ByteBuffer expectedBuffer =
                ByteBuffer.allocate(
                        FRAGMENT_ONE_UNENCRYPTED_DATA.length
                                + FRAGMENT_TWO_UNENCRYPTED_DATA.length);
        expectedBuffer.put(FRAGMENT_ONE_UNENCRYPTED_DATA).put(FRAGMENT_TWO_UNENCRYPTED_DATA);

        byte[] reassembledBytes = resultPartialComplete.reassembleAllFrags();
        assertArrayEquals(expectedBuffer.array(), reassembledBytes);
    }

    @Test
    public void testReassembleIncompleteFragmentsThrows() throws Exception {
        DecodeResultPartial resultPartial = makeDecodeResultForFragTwo(null /*collectedFragments*/);

        assertFalse(resultPartial.isAllFragmentsReceived());

        try {
            resultPartial.reassembleAllFrags();
            fail("Expected to fail because reassembly is not done");
        } catch (IllegalStateException expected) {

        }
    }

    private void setDecryptSkfPayload(IkeSkfPayload skf) throws Exception {
        doReturn(skf)
                .when(mSpyIkePayloadDecoder)
                .decodeIkeSkPayload(
                        eq(true),
                        anyBoolean(),
                        any(),
                        eq(mMockIntegrity),
                        eq(mMockCipher),
                        any(),
                        any());
    }

    private DecodeResult decodeSkf(
            int expectedMsgId,
            IkeHeader header,
            byte[] packet,
            DecodeResultPartial collectFragments)
            throws Exception {
        return IkeMessage.decode(
                expectedMsgId,
                mMockIntegrity,
                mMockCipher,
                mMockIkeSaRecord,
                header,
                packet,
                collectFragments);
    }

    @Test
    public void testRcvFirstArrivedFrag() throws Exception {
        setDecryptSkfPayload(mDummySkfPayloadTwo);
        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID,
                        mFragTwoHeader,
                        mIkeFragPacket,
                        null /* collectedFragments*/);

        // Verify decoding result
        assertTrue(decodeResult instanceof DecodeResultPartial);
        DecodeResultPartial resultPartial = (DecodeResultPartial) decodeResult;

        assertEquals(PAYLOAD_TYPE_NO_NEXT, resultPartial.firstPayloadType);
        assertEquals(mFragTwoHeader, resultPartial.ikeHeader);

        assertEquals(TOTAL_FRAGMENTS, resultPartial.collectedFragsList.length);
        assertArrayEquals(
                FRAGMENT_TWO_UNENCRYPTED_DATA,
                resultPartial.collectedFragsList[FRAGMENT_NUM_TWO - 1]);
        assertFalse(resultPartial.isAllFragmentsReceived());
    }

    @Test
    public void testRcvLastArrivedFrag() throws Exception {
        // Create two dummy SKF Payloads so that the complete unencrypted data is two ID payloads
        byte[] idInitPayloadBytes = TestUtils.hexStringToByteArray(ID_INIT_PAYLOAD_HEX_STRING);
        byte[] idRespPayloadBytes = TestUtils.hexStringToByteArray(ID_RESP_PAYLOAD_HEX_STRING);
        IkeSkfPayload skfOne =
                makeDummySkfPayload(idInitPayloadBytes, FRAGMENT_NUM_ONE, TOTAL_FRAGMENTS);
        IkeSkfPayload skfTwo =
                makeDummySkfPayload(idRespPayloadBytes, FRAGMENT_NUM_TWO, TOTAL_FRAGMENTS);

        DecodeResultPartial resultPartialIncomplete =
                new DecodeResultPartial(
                        mFragOneHeader,
                        skfOne,
                        PAYLOAD_TYPE_ID_INITIATOR,
                        null /* collectedFragments*/);

        setDecryptSkfPayload(skfTwo);
        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID,
                        mFragTwoHeader,
                        mIkeFragPacket,
                        resultPartialIncomplete);

        // Verify fragments reassembly has been finished and complete message has been decoded.
        assertTrue(decodeResult instanceof DecodeResultOk);
        DecodeResultOk resultOk = (DecodeResultOk) decodeResult;
        assertEquals(2, resultOk.ikeMessage.ikePayloadList.size());
    }

    @Test
    public void testRcvFirstArrivedFragWithUnprotectedError() throws Exception {
        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID + 1,
                        mFragTwoHeader,
                        mIkeFragPacket,
                        null /* collectedFragments*/);

        // Verify that unprotected error was returned
        IkeException ikeException =
                verifyDecodeResultErrorAndGetIkeException(
                        decodeResult, DECODE_STATUS_UNPROTECTED_ERROR);
        assertTrue(ikeException instanceof InvalidMessageIdException);
    }

    @Test
    public void testRcvLastArrivedFragWithUnprotectedError() throws Exception {
        DecodeResultPartial resultPartialIncomplete =
                makeDecodeResultForFragOne(null /* collectedFragments*/);

        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID + 1,
                        mFragTwoHeader,
                        mIkeFragPacket,
                        resultPartialIncomplete);

        // Verify that newly received fragment was discarded
        assertEquals(resultPartialIncomplete, decodeResult);
    }

    @Test
    public void testRcvFragWithLargerTotalFragments() throws Exception {
        DecodeResultPartial resultPartialIncomplete =
                new DecodeResultPartial(
                        mFragOneHeader,
                        mDummySkfPayloadOne,
                        PAYLOAD_TYPE_NO_NEXT,
                        null /* collectedFragments*/);

        // Set total fragments of inbound fragment to 5
        int totalFragments = 5;
        byte[] fragPacket = TestUtils.hexStringToByteArray(IKE_FRAG_HEX_STRING);
        fragPacket[TOTAL_FRAGMENTS_OFFSET] = 0;
        fragPacket[TOTAL_FRAGMENTS_OFFSET] = 5;

        byte[] unencryptedData = "testRcvFragWithLargerTotalFragments".getBytes();
        IkeSkfPayload skfPayload =
                makeDummySkfPayload(unencryptedData, FRAGMENT_NUM_TWO, totalFragments);
        setDecryptSkfPayload(skfPayload);
        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID,
                        mFragTwoHeader,
                        fragPacket,
                        resultPartialIncomplete);

        // Verify that previously collected fragments were all discarded
        assertTrue(decodeResult instanceof DecodeResultPartial);
        DecodeResultPartial resultPartial = (DecodeResultPartial) decodeResult;

        assertEquals(PAYLOAD_TYPE_NO_NEXT, resultPartial.firstPayloadType);
        assertEquals(mFragTwoHeader, resultPartial.ikeHeader);

        assertEquals(totalFragments, resultPartial.collectedFragsList.length);
        assertArrayEquals(unencryptedData, resultPartial.collectedFragsList[FRAGMENT_NUM_TWO - 1]);
        assertFalse(resultPartial.isAllFragmentsReceived());
    }

    @Test
    public void testRcvFragWithSmallerTotalFragments() throws Exception {
        int totalFragments = 5;
        byte[] unencryptedData = "testRcvFragWithSmallerTotalFragments".getBytes();
        IkeSkfPayload skfPayload =
                makeDummySkfPayload(unencryptedData, FRAGMENT_NUM_ONE, totalFragments);

        DecodeResultPartial resultPartialIncomplete =
                new DecodeResultPartial(
                        mFragOneHeader,
                        skfPayload,
                        PAYLOAD_TYPE_AUTH,
                        null /* collectedFragments*/);

        setDecryptSkfPayload(mDummySkfPayloadTwo);
        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID,
                        mFragTwoHeader,
                        mIkeFragPacket,
                        resultPartialIncomplete);

        // Verify that newly received fragment was discarded
        assertEquals(resultPartialIncomplete, decodeResult);
    }

    @Test
    public void testRcvReplayFrag() throws Exception {
        DecodeResultPartial resultPartialIncomplete =
                makeDecodeResultForFragTwo(null /* collectedFragments*/);

        setDecryptSkfPayload(mDummySkfPayloadTwo);
        DecodeResult decodeResult =
                decodeSkf(
                        IKE_FRAG_EXPECTED_MESSAGE_ID,
                        mFragTwoHeader,
                        mIkeFragPacket,
                        resultPartialIncomplete);

        // Verify that newly received fragment was discarded
        assertEquals(resultPartialIncomplete, decodeResult);
    }

    @Test
    public void testRcvCompleteMessageDuringReassembly() throws Exception {
        DecodeResultPartial resultPartialIncomplete =
                makeDecodeResultForFragTwo(null /* collectedFragments*/);

        DecodeResult decodeResult =
                decodeSkf(
                        IKE_AUTH_EXPECTED_MESSAGE_ID,
                        mIkeAuthHeader,
                        mIkeAuthPacket,
                        resultPartialIncomplete);

        // Verify that newly received IKE message was discarded
        assertEquals(resultPartialIncomplete, decodeResult);
    }

    @Test
    public void testEncodeAndEncryptFragments() throws Exception {
        int messageId = 1;
        int fragSize = 140;
        int expectedTotalFragments = 3;

        byte[] integrityKey = new byte[0];
        byte[] encryptionKey = new byte[0];
        byte[] iv = new byte[IKE_AUTH_CIPHER_IV_SIZE];

        when(mMockCipher.generateIv()).thenReturn(iv);
        when(mMockCipher.encrypt(any(), any(), any()))
                .thenAnswer(
                        (invocation) -> {
                            return (byte[]) invocation.getArguments()[0];
                        });

        IkeHeader ikeHeader =
                new IkeHeader(
                        INIT_SPI,
                        RESP_SPI,
                        IkePayload.PAYLOAD_TYPE_SK,
                        IkeHeader.EXCHANGE_TYPE_IKE_AUTH,
                        true /*isResp*/,
                        false /*fromInit*/,
                        messageId);

        byte[][] packetList =
                new IkeMessage.IkeMessageHelper()
                        .encryptAndEncode(
                                ikeHeader,
                                IkePayload.PAYLOAD_TYPE_AUTH,
                                mUnencryptedPaddedData,
                                mMockIntegrity,
                                mMockCipher,
                                integrityKey,
                                encryptionKey,
                                true /*supportFragment*/,
                                fragSize);

        assertEquals(expectedTotalFragments, packetList.length);

        IkeHeader expectedIkeHeader =
                new IkeHeader(
                        INIT_SPI,
                        RESP_SPI,
                        IkePayload.PAYLOAD_TYPE_SKF,
                        IkeHeader.EXCHANGE_TYPE_IKE_AUTH,
                        true /*isResp*/,
                        false /*fromInit*/,
                        messageId);
        for (int i = 0; i < packetList.length; i++) {
            byte[] p = packetList[i];

            // Verify fragment length
            assertNotNull(p);
            assertTrue(p.length <= fragSize);

            ByteBuffer packetBuffer = ByteBuffer.wrap(p);

            // Verify IKE header
            byte[] headerBytes = new byte[IkeHeader.IKE_HEADER_LENGTH];
            packetBuffer.get(headerBytes);

            ByteBuffer expectedHeadBuffer = ByteBuffer.allocate(IkeHeader.IKE_HEADER_LENGTH);
            expectedIkeHeader.encodeToByteBuffer(
                    expectedHeadBuffer, p.length - IkeHeader.IKE_HEADER_LENGTH);

            assertArrayEquals(expectedHeadBuffer.array(), headerBytes);

            // Verify fragment payload header
            packetBuffer.get(new byte[IkePayload.GENERIC_HEADER_LENGTH]);
            assertEquals(i + 1 /*expetced fragNum*/, Short.toUnsignedInt(packetBuffer.getShort()));
            assertEquals(expectedTotalFragments, Short.toUnsignedInt(packetBuffer.getShort()));
        }

        verify(mMockCipher, times(expectedTotalFragments + 1))
                .encrypt(any(), eq(encryptionKey), eq(iv));
    }
}
