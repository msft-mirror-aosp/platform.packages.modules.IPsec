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
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.util.Pair;

import com.android.ike.ikev2.exceptions.IkeException;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

public final class IkeSaPayloadTest {
    private static final String PROPOSAL_RAW_PACKET =
            "0000002c010100040300000c0100000c800e0080030000080300000203000008040"
                    + "000020000000802000002";
    private static final String TWO_PROPOSAL_RAW_PACKET =
            "020000dc010100190300000c0100000c800e00800300000c0100000c800e00c0030"
                    + "0000c0100000c800e01000300000801000003030000080300000c0300"
                    + "00080300000d030000080300000e03000008030000020300000803000"
                    + "005030000080200000503000008020000060300000802000007030000"
                    + "080200000403000008020000020300000804000013030000080400001"
                    + "40300000804000015030000080400001c030000080400001d03000008"
                    + "0400001e030000080400001f030000080400000f03000008040000100"
                    + "300000804000012000000080400000e000001000201001a0300000c01"
                    + "000014800e00800300000c01000014800e00c00300000c01000014800"
                    + "e01000300000c0100001c800e01000300000c01000013800e00800300"
                    + "000c01000013800e00c00300000c01000013800e01000300000c01000"
                    + "012800e00800300000c01000012800e00c00300000c01000012800e01"
                    + "000300000802000005030000080200000603000008020000070300000"
                    + "802000004030000080200000203000008040000130300000804000014"
                    + "0300000804000015030000080400001c030000080400001d030000080"
                    + "400001e030000080400001f030000080400000f030000080400001003"
                    + "00000804000012000000080400000e";
    private static final String TRANSFORM_RAW_PACKET = "0300000c0100000c800e0080";
    private static final String ATTRIBUTE_RAW_PACKET = "800e0080";

    private static final int PROPOSAL_NUMBER = 1;

    @IkeSaPayload.Proposal.ProtocolId
    private static final int PROPOSAL_PROTOCOL_ID = IkeSaPayload.Proposal.PROTOCOL_ID_IKE;

    private static final byte PROPOSAL_SPI_SIZE = 0;
    private static final byte PROPOSAL_SPI = 0;

    // Constants for multiple proposals test
    private static final byte[] PROPOSAL_NUMBER_LIST = {1, 2};

    private static final byte TRANSFORM_TYPE = 1;
    private static final byte TRANSFORM_ID = 12;

    private static final byte ATTRIBUTE_TYPE = 14;
    private static final byte[] ATTRIBUTE_VALUE = {(byte) 0x00, (byte) 0x80};

    @Test
    public void testDecodeAttribute() throws Exception {
        byte[] inputPacket = hexStringToByteArray(ATTRIBUTE_RAW_PACKET);
        ByteBuffer inputBuffer = ByteBuffer.wrap(inputPacket);

        Pair<IkeSaPayload.Attribute, Integer> pair = IkeSaPayload.Attribute.readFrom(inputBuffer);
        IkeSaPayload.Attribute attribute = pair.first;

        assertEquals(ATTRIBUTE_TYPE, attribute.type);
        assertEquals(ATTRIBUTE_VALUE.length, attribute.value.length);
        for (int i = 0; i < ATTRIBUTE_VALUE.length; i++) {
            assertEquals(ATTRIBUTE_VALUE[i], attribute.value[i]);
        }
    }

    @Test
    public void testDecodeTransform() throws Exception {
        byte[] inputPacket = hexStringToByteArray(TRANSFORM_RAW_PACKET);
        ByteBuffer inputBuffer = ByteBuffer.wrap(inputPacket);
        IkeSaPayload.AttributeDecoder mockedDecoder = mock(IkeSaPayload.AttributeDecoder.class);
        List<IkeSaPayload.Attribute> attributeList = new LinkedList<>();
        when(mockedDecoder.decodeAttributes(anyInt(), any())).thenReturn(attributeList);
        IkeSaPayload.Transform.sAttributeDecoder = mockedDecoder;

        IkeSaPayload.Transform transform = IkeSaPayload.Transform.readFrom(inputBuffer);

        assertEquals(TRANSFORM_TYPE, transform.type);
        assertEquals(TRANSFORM_ID, transform.id);
        assertEquals(0, transform.attributeList.size());
    }

    @Test
    public void testDecodeSingleProposal() throws Exception {
        byte[] inputPacket = hexStringToByteArray(PROPOSAL_RAW_PACKET);
        ByteBuffer inputBuffer = ByteBuffer.wrap(inputPacket);
        IkeSaPayload.TransformDecoder mockedDecoder = mock(IkeSaPayload.TransformDecoder.class);
        when(mockedDecoder.decodeTransforms(anyInt(), any()))
                .thenReturn(new IkeSaPayload.Transform[0]);
        IkeSaPayload.Proposal.sTransformDecoder = mockedDecoder;

        IkeSaPayload.Proposal proposal = IkeSaPayload.Proposal.readFrom(inputBuffer);

        assertEquals(PROPOSAL_NUMBER, proposal.number);
        assertEquals(PROPOSAL_PROTOCOL_ID, proposal.protocolId);
        assertEquals(PROPOSAL_SPI_SIZE, proposal.spiSize);
        assertEquals(PROPOSAL_SPI, proposal.spi);
        assertEquals(0, proposal.transformArray.length);
    }

    @Test
    public void testDecodeMultipleProposal() throws Exception {
        byte[] inputPacket = hexStringToByteArray(TWO_PROPOSAL_RAW_PACKET);
        IkeSaPayload.Proposal.sTransformDecoder =
                new IkeSaPayload.TransformDecoder() {
                    @Override
                    public IkeSaPayload.Transform[] decodeTransforms(
                            int count, ByteBuffer inputBuffer) throws IkeException {
                        for (int i = 0; i < count; i++) {
                            // Read length field and move position
                            inputBuffer.getShort();
                            int length = Short.toUnsignedInt(inputBuffer.getShort());
                            byte[] temp = new byte[length - 4];
                            inputBuffer.get(temp);
                        }
                        return new IkeSaPayload.Transform[0];
                    }
                };

        IkeSaPayload payload = new IkeSaPayload(false, inputPacket);

        assertEquals(PROPOSAL_NUMBER_LIST.length, payload.proposalList.size());
        for (int i = 0; i < payload.proposalList.size(); i++) {
            IkeSaPayload.Proposal proposal = payload.proposalList.get(i);
            assertEquals(PROPOSAL_NUMBER_LIST[i], proposal.number);
            assertEquals(IkeSaPayload.Proposal.PROTOCOL_ID_IKE, proposal.protocolId);
            assertEquals(0, proposal.spiSize);
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
