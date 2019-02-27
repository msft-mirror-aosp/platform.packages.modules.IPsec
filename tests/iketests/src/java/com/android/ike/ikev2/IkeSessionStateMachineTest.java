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

package com.android.ike.ikev2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.os.test.TestLooper;
import android.util.Pair;

import com.android.ike.ikev2.ChildSessionStateMachineFactory.ChildSessionFactoryHelper;
import com.android.ike.ikev2.ChildSessionStateMachineFactory.IChildSessionFactoryHelper;
import com.android.ike.ikev2.IkeSessionStateMachine.ReceivedIkePacket;
import com.android.ike.ikev2.SaRecord.ISaRecordHelper;
import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.SaRecord.SaRecordHelper;
import com.android.ike.ikev2.message.IkeHeader;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeMessage.IIkeMessageHelper;
import com.android.ike.ikev2.message.IkeMessage.IkeMessageHelper;
import com.android.ike.ikev2.message.IkePayload;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.LinkedList;

public final class IkeSessionStateMachineTest {

    private TestLooper mLooper;
    private IkeSessionStateMachine mIkeSessionStateMachine;

    private IIkeMessageHelper mMockIkeMessageHelper;
    private ISaRecordHelper mMockSaRecordHelper;
    private IkeSessionOptions mMockIkeSessionOptions;

    private ChildSessionStateMachine mMockChildSessionStateMachine;
    private ChildSessionOptions mMockChildSessionOptions;
    private IChildSessionFactoryHelper mMockChildSessionFactoryHelper;

    private IkeSaRecord mSpyCurrentIkeSaRecord;
    private IkeSaRecord mSpyLocalInitIkeSaRecord;
    private IkeSaRecord mSpyRemoteInitIkeSaRecord;

    private ReceivedIkePacket makeDummyUnencryptedReceivedIkePacket(int packetType)
            throws Exception {
        IkeMessage dummyIkeMessage = makeDummyIkeMessageForTest(0, 0, false, false);
        Pair<IkeHeader, byte[]> dummyIkePacketPair =
                new Pair<>(dummyIkeMessage.ikeHeader, new byte[0]);
        when(mMockIkeMessageHelper.decode(dummyIkePacketPair.first, dummyIkePacketPair.second))
                .thenReturn(dummyIkeMessage);
        when(mMockIkeMessageHelper.getMessageType(dummyIkeMessage)).thenReturn(packetType);
        return new ReceivedIkePacket(dummyIkePacketPair);
    }

    private ReceivedIkePacket makeDummyEncryptedReceivedIkePacket(
            int packetType, IkeSaRecord ikeSaRecord) throws Exception {
        boolean fromIkeInit = !ikeSaRecord.isLocalInit;
        IkeMessage dummyIkeMessage =
                makeDummyIkeMessageForTest(
                        ikeSaRecord.initiatorSpi, ikeSaRecord.responderSpi, fromIkeInit, true);
        Pair<IkeHeader, byte[]> dummyIkePacketPair =
                new Pair<>(dummyIkeMessage.ikeHeader, new byte[0]);
        when(mMockIkeMessageHelper.decode(
                        mMockIkeSessionOptions,
                        ikeSaRecord,
                        dummyIkePacketPair.first,
                        dummyIkePacketPair.second))
                .thenReturn(dummyIkeMessage);
        when(mMockIkeMessageHelper.getMessageType(dummyIkeMessage)).thenReturn(packetType);
        return new ReceivedIkePacket(dummyIkePacketPair);
    }

    private IkeMessage makeDummyIkeMessageForTest(
            long initSpi, long respSpi, boolean fromikeInit, boolean isEncrypted) {
        int firstPayloadType =
                isEncrypted ? IkePayload.PAYLOAD_TYPE_SK : IkePayload.PAYLOAD_TYPE_NO_NEXT;
        IkeHeader header =
                new IkeHeader(initSpi, respSpi, firstPayloadType, 0, true, fromikeInit, 0, 0);
        return new IkeMessage(header, new LinkedList<IkePayload>());
    }

    private void verifyDecodeEncryptedMessage(IkeSaRecord record, ReceivedIkePacket rcvPacket)
            throws Exception {
        verify(mMockIkeMessageHelper)
                .decode(
                        mMockIkeSessionOptions,
                        record,
                        rcvPacket.ikeHeader,
                        rcvPacket.ikePacketBytes);
    }

    public IkeSessionStateMachineTest() {
        mMockIkeMessageHelper = mock(IkeMessage.IIkeMessageHelper.class);
        mMockSaRecordHelper = mock(SaRecord.ISaRecordHelper.class);
        mMockIkeSessionOptions = mock(IkeSessionOptions.class);

        mMockChildSessionStateMachine = mock(ChildSessionStateMachine.class);
        mMockChildSessionOptions = mock(ChildSessionOptions.class);
        mMockChildSessionFactoryHelper = mock(IChildSessionFactoryHelper.class);

        mSpyCurrentIkeSaRecord = spy(new IkeSaRecord(11, 12, true, null, null));
        mSpyLocalInitIkeSaRecord = spy(new IkeSaRecord(21, 22, true, null, null));
        mSpyRemoteInitIkeSaRecord = spy(new IkeSaRecord(31, 32, false, null, null));

        when(mMockIkeMessageHelper.encode(any())).thenReturn(new byte[0]);
        when(mMockIkeMessageHelper.encode(any(), any(), any())).thenReturn(new byte[0]);
        when(mMockChildSessionFactoryHelper.makeChildSessionStateMachine(any(), any(), any()))
                .thenReturn(mMockChildSessionStateMachine);
    }

    @Before
    public void setUp() {
        // Setup thread and looper
        mLooper = new TestLooper();
        mIkeSessionStateMachine =
                new IkeSessionStateMachine(
                        "IkeSessionStateMachine",
                        mLooper.getLooper(),
                        mMockIkeSessionOptions,
                        mMockChildSessionOptions);
        mIkeSessionStateMachine.setDbg(true);
        mIkeSessionStateMachine.start();
        IkeMessage.setIkeMessageHelper(mMockIkeMessageHelper);
        SaRecord.setSaRecordHelper(mMockSaRecordHelper);
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                mMockChildSessionFactoryHelper);
    }

    @After
    public void tearDown() {
        mIkeSessionStateMachine.quit();
        mIkeSessionStateMachine.setDbg(false);
        IkeMessage.setIkeMessageHelper(new IkeMessageHelper());
        SaRecord.setSaRecordHelper(new SaRecordHelper());
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                new ChildSessionFactoryHelper());
    }

    @Test
    public void testCreateIkeLocalIkeInit() throws Exception {
        // Mock IKE_INIT response.
        ReceivedIkePacket dummyReceivedIkePacket =
                makeDummyUnencryptedReceivedIkePacket(IkeMessage.MESSAGE_TYPE_IKE_INIT_RESP);
        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any()))
                .thenReturn(mSpyCurrentIkeSaRecord);

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyReceivedIkePacket);

        mLooper.dispatchAll();
        verify(mMockIkeMessageHelper)
                .decode(dummyReceivedIkePacket.ikeHeader, dummyReceivedIkePacket.ikePacketBytes);
        verify(mMockIkeMessageHelper).getMessageType(any());
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.CreateIkeLocalIkeAuth);
    }

    private void mockIkeSetup() throws Exception {
        // Mock IKE_INIT response
        ReceivedIkePacket dummyIkeInitRespReceivedPacket =
                makeDummyUnencryptedReceivedIkePacket(IkeMessage.MESSAGE_TYPE_IKE_INIT_RESP);
        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any()))
                .thenReturn(mSpyCurrentIkeSaRecord);

        // Mock IKE_AUTH response
        ReceivedIkePacket dummyIkeAuthRespReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_IKE_AUTH_RESP, mSpyCurrentIkeSaRecord);

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyIkeInitRespReceivedPacket);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyIkeAuthRespReceivedPacket);
    }

    @Test
    public void testCreateIkeLocalIkeAuth() throws Exception {
        mockIkeSetup();

        mLooper.dispatchAll();
        verify(mMockIkeMessageHelper).decode(any(), any(), any(), any());
        verify(mMockIkeMessageHelper, times(2)).getMessageType(any());
        verify(mMockChildSessionStateMachine).handleFirstChildExchange(any(), any(), any());
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testRekeyIkeLocal() throws Exception {
        // Mock Rekey IKE response
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_REKEY_IKE_RESP, mSpyCurrentIkeSaRecord);
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);
        // Mock Delete old IKE response;
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_DELETE_IKE_RESP, mSpyCurrentIkeSaRecord);

        mockIkeSetup();

        // Testing creating new IKE
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRespReceivedPacket);
        // Testing deleting old IKE
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRespReceivedPacket);

        mLooper.dispatchAll();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRespReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, mSpyLocalInitIkeSaRecord);
    }

    @Test
    public void testRekeyIkeRemote() throws Exception {
        // Mock Rekey IKE request
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_REKEY_IKE_REQ, mSpyCurrentIkeSaRecord);
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord);

        // Mock Delete IKE request
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_DELETE_IKE_REQ, mSpyCurrentIkeSaRecord);
        mockIkeSetup();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRequestReceivedPacket);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRequestReceivedPacket);

        mLooper.dispatchAll();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRequestReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRequestReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, mSpyRemoteInitIkeSaRecord);
    }

    @Test
    public void testSimulRekey() throws Exception {
        // Mock Rekey IKE response
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_REKEY_IKE_RESP, mSpyCurrentIkeSaRecord);
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Mock Rekey IKE request
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_REKEY_IKE_REQ, mSpyCurrentIkeSaRecord);

        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord)
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Mock nonce comparison
        when(mSpyLocalInitIkeSaRecord.compareTo(mSpyRemoteInitIkeSaRecord)).thenReturn(1);

        // Mock Delete old IKE response;
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_DELETE_IKE_RESP, mSpyCurrentIkeSaRecord);

        // Mock Delete IKE request on remotely initiated IKE SA
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDummyEncryptedReceivedIkePacket(
                        IkeMessage.MESSAGE_TYPE_DELETE_IKE_REQ, mSpyRemoteInitIkeSaRecord);

        mockIkeSetup();

        // Testing creating new IKE
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRequestReceivedPacket);

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRespReceivedPacket);
        // Testing deleting old IKE and losing new IKE
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRespReceivedPacket);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRequestReceivedPacket);

        mLooper.dispatchAll();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRequestReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(
                mSpyRemoteInitIkeSaRecord, dummyDeleteIkeRequestReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, mSpyLocalInitIkeSaRecord);
    }
}
