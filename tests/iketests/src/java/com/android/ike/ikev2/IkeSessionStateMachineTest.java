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

import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.SOCK_DGRAM;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.IpSecSpiResponse;
import android.net.IpSecUdpEncapResponse;
import android.os.Looper;
import android.os.test.TestLooper;
import android.system.Os;

import androidx.test.InstrumentationRegistry;

import com.android.ike.ikev2.ChildSessionStateMachineFactory.ChildSessionFactoryHelper;
import com.android.ike.ikev2.ChildSessionStateMachineFactory.IChildSessionFactoryHelper;
import com.android.ike.ikev2.IkeIdentification.IkeIpv4AddrIdentification;
import com.android.ike.ikev2.IkeSessionStateMachine.IkeSecurityParameterIndex;
import com.android.ike.ikev2.IkeSessionStateMachine.ReceivedIkePacket;
import com.android.ike.ikev2.SaRecord.ISaRecordHelper;
import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.SaRecord.SaRecordHelper;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.message.IkeAuthPskPayload;
import com.android.ike.ikev2.message.IkeHeader;
import com.android.ike.ikev2.message.IkeIdPayload;
import com.android.ike.ikev2.message.IkeInformationalPayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeMessage.IIkeMessageHelper;
import com.android.ike.ikev2.message.IkeMessage.IkeMessageHelper;
import com.android.ike.ikev2.message.IkeNotifyPayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload;
import com.android.ike.ikev2.message.IkeSaPayload.DhGroupTransform;
import com.android.ike.ikev2.message.IkeSaPayload.EncryptionTransform;
import com.android.ike.ikev2.message.IkeSaPayload.EsnTransform;
import com.android.ike.ikev2.message.IkeSaPayload.IntegrityTransform;
import com.android.ike.ikev2.message.IkeSaPayload.PrfTransform;
import com.android.ike.ikev2.message.IkeTsPayload;
import com.android.ike.ikev2.message.TestUtils;
import com.android.server.IpSecService;

import libcore.net.InetAddressUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.Inet4Address;
import java.util.LinkedList;
import java.util.List;

public final class IkeSessionStateMachineTest {
    private static final Inet4Address LOCAL_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.200"));
    private static final Inet4Address REMOTE_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("127.0.0.1"));

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

    private static final String PSK_HEX_STRING = "6A756E69706572313233";

    private static final int NONCE_DATA_LEN = 32;

    private static final int KEY_LEN_IKE_INTE = 20;
    private static final int KEY_LEN_IKE_ENCR = 16;
    private static final int KEY_LEN_IKE_PRF = 20;
    private static final int KEY_LEN_IKE_SKD = KEY_LEN_IKE_PRF;

    private static final int DUMMY_CHILD_SPI_RESOURCE_ID_LOCAL = 0x1234;
    private static final int CHILD_SPI_LOCAL = 0x2ad4c0a2;

    private static final int DUMMY_UDP_ENCAP_RESOURCE_ID = 0x3234;
    private static final int UDP_ENCAP_PORT = 34567;

    private static long sIkeInitResponseSpiBase = 1L;

    private IpSecService mMockIpSecService;
    private IpSecManager mMockIpSecManager;
    private UdpEncapsulationSocket mUdpEncapSocket;

    private TestLooper mLooper;
    private IkeSessionStateMachine mIkeSessionStateMachine;

    private IkeSessionOptions mIkeSessionOptions;
    private ChildSessionOptions mChildSessionOptions;

    private EncryptionTransform mIkeEncryptionTransform;
    private IntegrityTransform mIkeIntegrityTransform;
    private PrfTransform mIkePrfTransform;
    private DhGroupTransform mIkeDhGroupTransform;

    private IIkeMessageHelper mMockIkeMessageHelper;
    private ISaRecordHelper mMockSaRecordHelper;

    private ChildSessionStateMachine mMockChildSessionStateMachine;
    private IChildSessionFactoryHelper mMockChildSessionFactoryHelper;

    private IkeSaRecord mSpyCurrentIkeSaRecord;
    private IkeSaRecord mSpyLocalInitIkeSaRecord;
    private IkeSaRecord mSpyRemoteInitIkeSaRecord;

    private int mExpectedCurrentSaLocalReqMsgId;
    private int mExpectedCurrentSaRemoteReqMsgId;

    private ArgumentCaptor<IkeMessage> mIkeMessageCaptor =
            ArgumentCaptor.forClass(IkeMessage.class);
    private ArgumentCaptor<IkeMacPrf> mIkePrfCaptor = ArgumentCaptor.forClass(IkeMacPrf.class);

    private ReceivedIkePacket makeDummyUnencryptedReceivedIkePacket(
            long initiatorSpi,
            long responderSpi,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            boolean fromIkeInit,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {

        IkeMessage dummyIkeMessage =
                makeDummyIkeMessageForTest(
                        initiatorSpi,
                        responderSpi,
                        eType,
                        isResp,
                        fromIkeInit,
                        0,
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
                        isResp
                                ? ikeSaRecord.getLocalRequestMessageId()
                                : ikeSaRecord.getRemoteRequestMessageId(),
                        true /*isEncyprted*/,
                        payloadTypeList,
                        payloadHexStringList);

        byte[] dummyIkePacketBytes = new byte[0];
        when(mMockIkeMessageHelper.decode(
                        any(),
                        any(),
                        eq(ikeSaRecord),
                        eq(dummyIkeMessage.ikeHeader),
                        eq(dummyIkePacketBytes)))
                .thenReturn(dummyIkeMessage);

        return new ReceivedIkePacket(dummyIkeMessage.ikeHeader, dummyIkePacketBytes);
    }

    private IkeMessage makeDummyIkeMessageForTest(
            long initSpi,
            long respSpi,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            boolean fromikeInit,
            int messageId,
            boolean isEncrypted,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {
        int firstPayloadType =
                isEncrypted ? IkePayload.PAYLOAD_TYPE_SK : IkePayload.PAYLOAD_TYPE_NO_NEXT;

        IkeHeader header =
                new IkeHeader(
                        initSpi, respSpi, firstPayloadType, eType, isResp, fromikeInit, messageId);

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
                .decode(
                        any(),
                        any(),
                        eq(record),
                        eq(rcvPacket.ikeHeader),
                        eq(rcvPacket.ikePacketBytes));
    }

    public IkeSessionStateMachineTest() throws Exception {
        mMockIkeMessageHelper = mock(IkeMessage.IIkeMessageHelper.class);
        mMockSaRecordHelper = mock(SaRecord.ISaRecordHelper.class);

        mMockChildSessionStateMachine = mock(ChildSessionStateMachine.class);
        mMockChildSessionFactoryHelper = mock(IChildSessionFactoryHelper.class);

        when(mMockIkeMessageHelper.encode(any())).thenReturn(new byte[0]);
        when(mMockIkeMessageHelper.encryptAndEncode(any(), any(), any(), any()))
                .thenReturn(new byte[0]);
        when(mMockChildSessionFactoryHelper.makeChildSessionStateMachine(
                        any(), any(), any(), any(), any()))
                .thenReturn(mMockChildSessionStateMachine);
    }

    private static IkeSaRecord makeDummyIkeSaRecord(
            long initSpi, long respSpi, boolean isLocalInit) {
        return new IkeSaRecord(
                initSpi,
                respSpi,
                isLocalInit,
                new byte[NONCE_DATA_LEN],
                new byte[NONCE_DATA_LEN],
                new byte[KEY_LEN_IKE_SKD],
                new byte[KEY_LEN_IKE_INTE],
                new byte[KEY_LEN_IKE_INTE],
                new byte[KEY_LEN_IKE_ENCR],
                new byte[KEY_LEN_IKE_ENCR],
                new byte[KEY_LEN_IKE_PRF],
                new byte[KEY_LEN_IKE_PRF]);
    }

    @Before
    public void setUp() throws Exception {
        setUpIpSecService();
        Context context = InstrumentationRegistry.getContext();
        mMockIpSecManager = new IpSecManager(context, mMockIpSecService);

        mUdpEncapSocket = mMockIpSecManager.openUdpEncapsulationSocket();

        mIkeSessionOptions = buildIkeSessionOptions();
        mChildSessionOptions = buildChildSessionOptions();

        mIkeEncryptionTransform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128);
        mIkeIntegrityTransform =
                new IntegrityTransform(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96);
        mIkePrfTransform = new PrfTransform(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1);
        mIkeDhGroupTransform = new DhGroupTransform(SaProposal.DH_GROUP_1024_BIT_MODP);

        // Setup thread and looper
        mLooper = new TestLooper();
        mIkeSessionStateMachine =
                new IkeSessionStateMachine(
                        "IkeSessionStateMachine",
                        mLooper.getLooper(),
                        mMockIpSecManager,
                        mIkeSessionOptions,
                        mChildSessionOptions);
        mIkeSessionStateMachine.setDbg(true);
        mIkeSessionStateMachine.start();

        IkeMessage.setIkeMessageHelper(mMockIkeMessageHelper);
        SaRecord.setSaRecordHelper(mMockSaRecordHelper);
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                mMockChildSessionFactoryHelper);

        mSpyCurrentIkeSaRecord = spy(makeDummyIkeSaRecord(11, 12, true));
        mSpyLocalInitIkeSaRecord = spy(makeDummyIkeSaRecord(21, 22, true));
        mSpyRemoteInitIkeSaRecord = spy(makeDummyIkeSaRecord(31, 32, false));

        mExpectedCurrentSaLocalReqMsgId = 0;
        mExpectedCurrentSaRemoteReqMsgId = 0;
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

    private void setUpIpSecService() throws Exception {
        mMockIpSecService = mock(IpSecService.class);

        when(mMockIpSecService.allocateSecurityParameterIndex(
                        eq(REMOTE_ADDRESS.getHostAddress()), anyInt(), anyObject()))
                .thenReturn(
                        new IpSecSpiResponse(
                                IpSecManager.Status.OK,
                                DUMMY_CHILD_SPI_RESOURCE_ID_LOCAL,
                                CHILD_SPI_LOCAL));

        when(mMockIpSecService.openUdpEncapsulationSocket(anyInt(), anyObject()))
                .thenReturn(
                        new IpSecUdpEncapResponse(
                                IpSecManager.Status.OK,
                                DUMMY_UDP_ENCAP_RESOURCE_ID,
                                UDP_ENCAP_PORT,
                                Os.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)));
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

        byte[] psk = TestUtils.hexStringToByteArray(PSK_HEX_STRING);

        IkeSessionOptions sessionOptions =
                new IkeSessionOptions.Builder(REMOTE_ADDRESS, mUdpEncapSocket)
                        .addSaProposal(saProposal)
                        .setLocalIdentification(
                                new IkeIpv4AddrIdentification((Inet4Address) LOCAL_ADDRESS))
                        .setRemoteIdentification(
                                new IkeIpv4AddrIdentification((Inet4Address) REMOTE_ADDRESS))
                        .setLocalAuthPsk(psk)
                        .setRemoteAuthPsk(psk)
                        .build();
        return sessionOptions;
    }

    private ChildSessionOptions buildChildSessionOptions() throws Exception {
        SaProposal saProposal =
                SaProposal.Builder.newChildSaProposalBuilder(true /*isFirstChildSaProposal*/)
                        .addEncryptionAlgorithm(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128)
                        .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                        .build();

        return new ChildSessionOptions.Builder().addSaProposal(saProposal).build();
    }

    private ReceivedIkePacket makeIkeInitResponse() throws Exception {
        // TODO: Build real IKE INIT response when IKE INIT response validation is implemented.
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_KE);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NONCE);

        payloadHexStringList.add(IKE_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(KE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NONCE_PAYLOAD_HEX_STRING);

        // In each test assign different IKE responder SPI in IKE INIT response to avoid remote SPI
        // collision during response validation.
        // STOPSHIP: b/131617794 allow #mockIkeSetup to be independent in each test after we can
        // support IkeSession cleanup.
        return makeDummyUnencryptedReceivedIkePacket(
                1L /*initiatorSpi*/,
                ++sIkeInitResponseSpiBase,
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

    private ReceivedIkePacket makeDeleteIkeResponse(IkeSaRecord ikeSaRecord) throws Exception {
        // TODO: Build real Delete IKE response when Delete IKE response validation is implemented.
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();
        return makeDummyEncryptedReceivedIkePacket(
                ikeSaRecord,
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

    private void verifyIncrementLocaReqMsgId() {
        assertEquals(
                ++mExpectedCurrentSaLocalReqMsgId,
                mSpyCurrentIkeSaRecord.getLocalRequestMessageId());
    }

    private void verifyIncrementRemoteReqMsgId() {
        assertEquals(
                ++mExpectedCurrentSaRemoteReqMsgId,
                mSpyCurrentIkeSaRecord.getRemoteRequestMessageId());
    }

    @Test
    public void testAllocateIkeSpi() throws Exception {
        // Test randomness.
        IkeSecurityParameterIndex ikeSpiOne =
                IkeSecurityParameterIndex.allocateSecurityParameterIndex(LOCAL_ADDRESS);
        IkeSecurityParameterIndex ikeSpiTwo =
                IkeSecurityParameterIndex.allocateSecurityParameterIndex(LOCAL_ADDRESS);

        assertNotEquals(ikeSpiOne.getSpi(), ikeSpiTwo.getSpi());
        ikeSpiTwo.close();

        // Test duplicate SPIs.
        long spiValue = ikeSpiOne.getSpi();
        try {
            IkeSecurityParameterIndex.allocateSecurityParameterIndex(LOCAL_ADDRESS, spiValue);
            fail("Expected to fail because duplicate SPI was assigned to the same address.");
        } catch (IOException expected) {

        }

        ikeSpiOne.close();
        IkeSecurityParameterIndex ikeSpiThree =
                IkeSecurityParameterIndex.allocateSecurityParameterIndex(LOCAL_ADDRESS, spiValue);
        ikeSpiThree.close();
    }

    @Test
    public void testCreateIkeLocalIkeInit() throws Exception {
        if (Looper.myLooper() == null) Looper.myLooper().prepare();
        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(mSpyCurrentIkeSaRecord);

        // Send IKE INIT request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);

        // Receive IKE INIT response
        ReceivedIkePacket dummyReceivedIkePacket = makeIkeInitResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyReceivedIkePacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

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

        // Validate negotiated SA proposal.
        SaProposal negotiatedProposal = mIkeSessionStateMachine.mSaProposal;
        assertNotNull(negotiatedProposal);

        assertEquals(
                new EncryptionTransform[] {mIkeEncryptionTransform},
                negotiatedProposal.getEncryptionTransforms());
        assertEquals(
                new IntegrityTransform[] {mIkeIntegrityTransform},
                negotiatedProposal.getIntegrityTransforms());
        assertEquals(new PrfTransform[] {mIkePrfTransform}, negotiatedProposal.getPrfTransforms());
        assertEquals(new EsnTransform[0], negotiatedProposal.getEsnTransforms());

        // Validate current IkeSaRecord.
        verify(mMockSaRecordHelper)
                .makeFirstIkeSaRecord(
                        any(IkeMessage.class),
                        any(IkeMessage.class),
                        mIkePrfCaptor.capture(),
                        eq(KEY_LEN_IKE_INTE),
                        eq(KEY_LEN_IKE_ENCR));

        IkeMacPrf negotiatedPrf = mIkePrfCaptor.getValue();
        assertEquals(KEY_LEN_IKE_PRF, negotiatedPrf.getKeyLength());
    }

    private void mockIkeSetup() throws Exception {
        if (Looper.myLooper() == null) Looper.myLooper().prepare();

        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(mSpyCurrentIkeSaRecord);

        // Send IKE INIT request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);

        // Receive IKE INIT response
        ReceivedIkePacket dummyIkeInitRespReceivedPacket = makeIkeInitResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyIkeInitRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Receive IKE AUTH response
        ReceivedIkePacket dummyIkeAuthRespReceivedPacket = makeIkeAuthResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyIkeAuthRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();
    }

    @Test
    public void testCreateIkeLocalIkeAuth() throws Exception {
        mockIkeSetup();

        mLooper.dispatchAll();

        // Validate outbound IKE AUTH request
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());
        IkeMessage ikeAuthReqMessage = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = ikeAuthReqMessage.ikeHeader;
        assertEquals(IkeHeader.EXCHANGE_TYPE_IKE_AUTH, ikeHeader.exchangeType);
        assertFalse(ikeHeader.isResponseMsg);
        assertTrue(ikeHeader.fromIkeInitiator);

        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_ID_INITIATOR, IkeIdPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_ID_RESPONDER, IkeIdPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_AUTH, IkeAuthPskPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_TS_INITIATOR, IkeTsPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_TS_RESPONDER, IkeTsPayload.class));

        verify(mMockIkeMessageHelper).decode(any(), any(), any(), any(), any());
        verify(mMockChildSessionStateMachine).handleFirstChildExchange(any(), any(), any());
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testRekeyIkeLocal() throws Exception {
        mockIkeSetup();
        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Send Rekey request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE);

        // Receive Rekey response
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket = makeRekeyIkeResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Receive Delete response
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Verify
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRespReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, mSpyLocalInitIkeSaRecord);
    }

    @Test
    public void testRekeyIkeRemote() throws Exception {
        mockIkeSetup();

        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord);

        // Receive Rekey request
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket = makeRekeyIkeRequest();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRequestReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementRemoteReqMsgId();

        // Rekey Delete request
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDeleteIkeRequest(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRequestReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementRemoteReqMsgId();

        // Verify
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRequestReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRequestReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, mSpyRemoteInitIkeSaRecord);
    }

    @Test
    public void testSimulRekey() throws Exception {
        mockIkeSetup();

        when(mMockSaRecordHelper.makeNewIkeSaRecord(eq(mSpyCurrentIkeSaRecord), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord)
                .thenReturn(mSpyLocalInitIkeSaRecord);
        when(mSpyLocalInitIkeSaRecord.compareTo(mSpyRemoteInitIkeSaRecord)).thenReturn(1);

        // Send Rekey request on mSpyCurrentIkeSaRecord
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE);

        // Receive Rekey request on mSpyCurrentIkeSaRecord
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket = makeRekeyIkeRequest();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRequestReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementRemoteReqMsgId();

        // Receive Rekey response on mSpyCurrentIkeSaRecord
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket = makeRekeyIkeResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Receive Delete response on mSpyCurrentIkeSaRecord
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Receive Delete request on mSpyRemoteInitIkeSaRecord
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDeleteIkeRequest(mSpyRemoteInitIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRequestReceivedPacket);
        mLooper.dispatchAll();
        assertEquals(
                mExpectedCurrentSaRemoteReqMsgId,
                mSpyCurrentIkeSaRecord.getRemoteRequestMessageId());

        // Verify
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRequestReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(
                mSpyRemoteInitIkeSaRecord, dummyDeleteIkeRequestReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, mSpyLocalInitIkeSaRecord);
    }

    @Test
    public void testBuildEncryptedInformationalMessage() throws Exception {
        IkeNotifyPayload payload =
                new IkeNotifyPayload(IkeNotifyPayload.NOTIFY_TYPE_INVALID_SYNTAX, new byte[0]);

        boolean isResp = true;
        IkeMessage generated =
                mIkeSessionStateMachine.buildEncryptedInformationalMessage(
                        mSpyCurrentIkeSaRecord, new IkeInformationalPayload[] {payload}, isResp, 0);

        assertEquals(mSpyCurrentIkeSaRecord.initiatorSpi, generated.ikeHeader.ikeInitiatorSpi);
        assertEquals(mSpyCurrentIkeSaRecord.responderSpi, generated.ikeHeader.ikeResponderSpi);
        assertEquals(mSpyCurrentIkeSaRecord.getMessageId(), generated.ikeHeader.messageId);
        assertEquals(isResp, generated.ikeHeader.isResponseMsg);
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, generated.ikeHeader.nextPayloadType);

        List<IkeNotifyPayload> generatedPayloads =
                generated.getPayloadListForType(
                        IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);
        assertEquals(1, generatedPayloads.size());

        IkeNotifyPayload generatedPayload = generatedPayloads.get(0);
        assertArrayEquals(new byte[0], generatedPayload.notifyData);
        assertEquals(IkeNotifyPayload.NOTIFY_TYPE_INVALID_SYNTAX, generatedPayload.notifyType);
    }
}
