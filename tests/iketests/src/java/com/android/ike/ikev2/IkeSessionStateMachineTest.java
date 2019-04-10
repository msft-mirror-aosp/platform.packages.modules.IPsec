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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Looper;
import android.os.test.TestLooper;

import androidx.test.InstrumentationRegistry;

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
import com.android.ike.ikev2.message.TestUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.List;

public final class IkeSessionStateMachineTest {

    private static final String SERVER_ADDRESS = "192.0.2.100";

    private static final String IKE_SA_PAYLOAD_HEX_STRING =
            "220000300000002c010100040300000c0100000c800e00800300000803000002030"
                    + "00008020000020000000804000002";
    private static final String KE_PAYLOAD_HEX_STRING =
            "2800008800020000b4a2faf4bb54878ae21d638512ece55d9236fc50"
                    + "46ab6cef82220f421f3ce6361faf36564ecb6d28798a94aa"
                    + "d7b2b4b603ddeaaa5630adb9ece8ac37534036040610ebdd"
                    + "92f46bef84f0be7db860351843858f8acf87056e272377f7"
                    + "0c9f2d81e29c7b0ce4f291a3a72476bb0b278fd4b7b0a4c2"
                    + "6bbeb08214c7071376079587";
    private static final String NONCE_PAYLOAD_HEX_STRING =
            "29000024c39b7f368f4681b89fa9b7be6465abd7c5f68b6ed5d3b4c72cb4240eb5c46412";
    private static final String DELETE_IKE_PAYLOAD_HEX_STRING = "0000000801000000";
    private static final String NOTIFY_REKEY_IKE_PAYLOAD_HEX_STRING = "2100000800004009";

    private UdpEncapsulationSocket mUdpEncapSocket;

    private TestLooper mLooper;
    private IkeSessionStateMachine mIkeSessionStateMachine;

    private IkeSessionOptions mIkeSessionOptions;
    private ChildSessionOptions mChildSessionOptions;

    private IIkeMessageHelper mMockIkeMessageHelper;
    private ISaRecordHelper mMockSaRecordHelper;

    private ChildSessionStateMachine mMockChildSessionStateMachine;
    private IChildSessionFactoryHelper mMockChildSessionFactoryHelper;

    private IkeSaRecord mSpyCurrentIkeSaRecord;
    private IkeSaRecord mSpyLocalInitIkeSaRecord;
    private IkeSaRecord mSpyRemoteInitIkeSaRecord;

    private ArgumentCaptor<IkeMessage> mIkeMessageCaptor =
            ArgumentCaptor.forClass(IkeMessage.class);

    private ReceivedIkePacket makeDummyUnencryptedReceivedIkePacket(
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            boolean fromIkeInit,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {

        IkeMessage dummyIkeMessage =
                makeDummyIkeMessageForTest(
                        0 /*initSpi*/,
                        0 /*respSpi*/,
                        eType,
                        isResp,
                        fromIkeInit,
                        false /*isEncrypted*/,
                        payloadTypeList,
                        payloadHexStringList);

        byte[] dummyIkePacketBytes = new byte[0];
        when(mMockIkeMessageHelper.decode(dummyIkeMessage.ikeHeader, dummyIkePacketBytes))
                .thenReturn(dummyIkeMessage);

        return new ReceivedIkePacket(dummyIkeMessage.ikeHeader, dummyIkePacketBytes);
    }

    private ReceivedIkePacket makeDummyEncryptedReceivedIkePacket(
            IkeSaRecord ikeSaRecord,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {

        boolean fromIkeInit = !ikeSaRecord.isLocalInit;

        IkeMessage dummyIkeMessage =
                makeDummyIkeMessageForTest(
                        ikeSaRecord.initiatorSpi,
                        ikeSaRecord.responderSpi,
                        eType,
                        isResp,
                        fromIkeInit,
                        true /*isEncyprted*/,
                        payloadTypeList,
                        payloadHexStringList);

        byte[] dummyIkePacketBytes = new byte[0];
        when(mMockIkeMessageHelper.decode(
                        mIkeSessionOptions,
                        ikeSaRecord,
                        dummyIkeMessage.ikeHeader,
                        dummyIkePacketBytes))
                .thenReturn(dummyIkeMessage);

        return new ReceivedIkePacket(dummyIkeMessage.ikeHeader, dummyIkePacketBytes);
    }

    private IkeMessage makeDummyIkeMessageForTest(
            long initSpi,
            long respSpi,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            boolean fromikeInit,
            boolean isEncrypted,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {
        int firstPayloadType =
                isEncrypted ? IkePayload.PAYLOAD_TYPE_SK : IkePayload.PAYLOAD_TYPE_NO_NEXT;

        IkeHeader header =
                new IkeHeader(
                        initSpi,
                        respSpi,
                        firstPayloadType,
                        eType,
                        isResp,
                        fromikeInit,
                        0 /*msgId*/);

        List<IkePayload> payloadList = new LinkedList<>();
        for (int i = 0; i < payloadTypeList.size(); i++) {
            payloadList.add(
                    TestUtils.hexStringToIkePayload(
                            payloadTypeList.get(i), isResp, payloadHexStringList.get(i)));
        }

        return new IkeMessage(header, payloadList);
    }

    private void verifyDecodeEncryptedMessage(IkeSaRecord record, ReceivedIkePacket rcvPacket)
            throws Exception {
        verify(mMockIkeMessageHelper)
                .decode(mIkeSessionOptions, record, rcvPacket.ikeHeader, rcvPacket.ikePacketBytes);
    }

    public IkeSessionStateMachineTest() throws Exception {
        mMockIkeMessageHelper = mock(IkeMessage.IIkeMessageHelper.class);
        mMockSaRecordHelper = mock(SaRecord.ISaRecordHelper.class);

        mMockChildSessionStateMachine = mock(ChildSessionStateMachine.class);
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
    public void setUp() throws Exception {
        Context context = InstrumentationRegistry.getContext();
        IpSecManager ipSecManager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
        mUdpEncapSocket = ipSecManager.openUdpEncapsulationSocket();

        mIkeSessionOptions = buildIkeSessionOptions();
        mChildSessionOptions = new ChildSessionOptions();

        // Setup thread and looper
        mLooper = new TestLooper();
        mIkeSessionStateMachine =
                new IkeSessionStateMachine(
                        "IkeSessionStateMachine",
                        mLooper.getLooper(),
                        mIkeSessionOptions,
                        mChildSessionOptions);
        mIkeSessionStateMachine.setDbg(true);
        mIkeSessionStateMachine.start();

        IkeMessage.setIkeMessageHelper(mMockIkeMessageHelper);
        SaRecord.setSaRecordHelper(mMockSaRecordHelper);
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                mMockChildSessionFactoryHelper);
    }

    @After
    public void tearDown() throws Exception {
        mIkeSessionStateMachine.quit();
        mIkeSessionStateMachine.setDbg(false);
        mUdpEncapSocket.close();

        IkeMessage.setIkeMessageHelper(new IkeMessageHelper());
        SaRecord.setSaRecordHelper(new SaRecordHelper());
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                new ChildSessionFactoryHelper());
    }

    private IkeSessionOptions buildIkeSessionOptions() throws Exception {
        SaProposal saProposal =
                SaProposal.Builder.newIkeSaProposalBuilder()
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                        .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1)
                        .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                        .build();

        InetAddress serveAddress = InetAddress.getByName(SERVER_ADDRESS);
        IkeSessionOptions sessionOptions =
                new IkeSessionOptions.Builder(serveAddress, mUdpEncapSocket)
                        .addSaProposal(saProposal)
                        .build();
        return sessionOptions;
    }

    private ReceivedIkePacket makeIkeInitResponse() throws Exception {
        // TODO: Build real IKE INIT response when IKE INIT response validation is implemented.
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();
        return makeDummyUnencryptedReceivedIkePacket(
                IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT,
                true /*isResp*/,
                false /*fromIkeInit*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeIkeAuthResponse() throws Exception {
        // TODO: Build real IKE_AUTH response when IKE AUTH response validation is implemented.
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();
        return makeDummyEncryptedReceivedIkePacket(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_IKE_AUTH,
                true /*isResp*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeRekeyIkeResponse() throws Exception {
        // TODO: Build real Rekey IKE response when Rekey IKE response validation is implemented.
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();
        return makeDummyEncryptedReceivedIkePacket(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                true /*isResp*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeDeleteIkeResponse(IkeSaRecord saRecord) throws Exception {
        // TODO: Build real Delete IKE response when Delete IKE response validation is implemented.
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();
        return makeDummyEncryptedReceivedIkePacket(
                saRecord,
                IkeHeader.EXCHANGE_TYPE_INFORMATIONAL,
                true /*isResp*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeRekeyIkeRequest() throws Exception {
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NOTIFY);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_KE);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NONCE);

        payloadHexStringList.add(NOTIFY_REKEY_IKE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(IKE_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(KE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NONCE_PAYLOAD_HEX_STRING);
        return makeDummyEncryptedReceivedIkePacket(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                false /*isResp*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeDeleteIkeRequest(IkeSaRecord saRecord) throws Exception {
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_DELETE);

        payloadHexStringList.add(DELETE_IKE_PAYLOAD_HEX_STRING);

        return makeDummyEncryptedReceivedIkePacket(
                saRecord,
                IkeHeader.EXCHANGE_TYPE_INFORMATIONAL,
                false /*isResp*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private static boolean isIkePayloadExist(
            List<IkePayload> payloadList, @IkePayload.PayloadType int payloadType) {
        for (IkePayload payload : payloadList) {
            if (payload.payloadType == payloadType) return true;
        }
        return false;
    }

    @Test
    public void testCreateIkeLocalIkeInit() throws Exception {
        if (Looper.myLooper() == null) Looper.myLooper().prepare();
        // Mock IKE_INIT response.
        ReceivedIkePacket dummyReceivedIkePacket = makeIkeInitResponse();

        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any()))
                .thenReturn(mSpyCurrentIkeSaRecord);

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyReceivedIkePacket);

        mLooper.dispatchAll();

        // Validate outbound IKE INIT request
        verify(mMockIkeMessageHelper).encode(mIkeMessageCaptor.capture());
        IkeMessage ikeInitReqMessage = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = ikeInitReqMessage.ikeHeader;
        assertEquals(IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT, ikeHeader.exchangeType);
        assertFalse(ikeHeader.isResponseMsg);
        assertTrue(ikeHeader.fromIkeInitiator);

        List<IkePayload> payloadList = ikeInitReqMessage.ikePayloadList;
        assertTrue(isIkePayloadExist(payloadList, IkePayload.PAYLOAD_TYPE_SA));
        assertTrue(isIkePayloadExist(payloadList, IkePayload.PAYLOAD_TYPE_KE));
        assertTrue(isIkePayloadExist(payloadList, IkePayload.PAYLOAD_TYPE_NONCE));

        IkeSocket ikeSocket = mIkeSessionStateMachine.mIkeSocket;
        assertNotNull(ikeSocket);
        assertNotEquals(
                -1 /*not found*/, ikeSocket.mSpiToIkeSession.indexOfValue(mIkeSessionStateMachine));

        verify(mMockIkeMessageHelper)
                .decode(dummyReceivedIkePacket.ikeHeader, dummyReceivedIkePacket.ikePacketBytes);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.CreateIkeLocalIkeAuth);
    }

    private void mockIkeSetup() throws Exception {
        if (Looper.myLooper() == null) Looper.myLooper().prepare();
        // Mock IKE_INIT response
        ReceivedIkePacket dummyIkeInitRespReceivedPacket = makeIkeInitResponse();
        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any()))
                .thenReturn(mSpyCurrentIkeSaRecord);

        // Mock IKE_AUTH response
        ReceivedIkePacket dummyIkeAuthRespReceivedPacket = makeIkeAuthResponse();

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
        verify(mMockChildSessionStateMachine).handleFirstChildExchange(any(), any(), any());
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testRekeyIkeLocal() throws Exception {
        // Mock Rekey IKE response
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket = makeRekeyIkeResponse();
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);
        // Mock Delete old IKE response;
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);

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
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket = makeRekeyIkeRequest();
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord);

        // Mock Delete IKE request
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDeleteIkeRequest(mSpyCurrentIkeSaRecord);

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
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket = makeRekeyIkeResponse();
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Mock Rekey IKE request
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket = makeRekeyIkeRequest();

        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord)
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Mock nonce comparison
        when(mSpyLocalInitIkeSaRecord.compareTo(mSpyRemoteInitIkeSaRecord)).thenReturn(1);

        // Mock Delete old IKE response;
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);

        // Mock Delete IKE request on remotely initiated IKE SA
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDeleteIkeRequest(mSpyRemoteInitIkeSaRecord);

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
