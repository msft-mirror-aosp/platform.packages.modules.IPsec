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

import static com.android.ike.ikev2.ChildSessionStateMachine.CMD_FORCE_TRANSITION;
import static com.android.ike.ikev2.IkeSessionStateMachine.IKE_EXCHANGE_SUBTYPE_DELETE_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.IKE_EXCHANGE_SUBTYPE_REKEY_CHILD;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_INFORMATIONAL;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_REKEY_SA;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_DELETE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_KE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NONCE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_SA;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_TS_INITIATOR;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_TS_RESPONDER;
import static com.android.ike.ikev2.message.IkePayload.PROTOCOL_ID_ESP;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Handler;
import android.os.Looper;
import android.os.test.TestLooper;

import androidx.test.InstrumentationRegistry;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.ChildSessionStateMachine.CreateChildSaHelper;
import com.android.ike.ikev2.ChildSessionStateMachine.IChildSessionSmCallback;
import com.android.ike.ikev2.SaRecord.ChildSaRecord;
import com.android.ike.ikev2.SaRecord.ChildSaRecordConfig;
import com.android.ike.ikev2.SaRecord.ISaRecordHelper;
import com.android.ike.ikev2.SaRecord.SaRecordHelper;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.exceptions.InvalidKeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.message.IkeDeletePayload;
import com.android.ike.ikev2.message.IkeKePayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkeNotifyPayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload;
import com.android.ike.ikev2.message.IkeSaPayload.DhGroupTransform;
import com.android.ike.ikev2.message.IkeSaPayload.EncryptionTransform;
import com.android.ike.ikev2.message.IkeSaPayload.IntegrityTransform;
import com.android.ike.ikev2.message.IkeSaPayload.PrfTransform;
import com.android.ike.ikev2.message.IkeTestUtils;
import com.android.ike.ikev2.message.IkeTsPayload;
import com.android.server.IpSecService;

import libcore.net.InetAddressUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public final class ChildSessionStateMachineTest {
    private static final Inet4Address LOCAL_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.200"));
    private static final Inet4Address REMOTE_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.100"));

    private static final String IKE_AUTH_RESP_SA_PAYLOAD =
            "2c00002c0000002801030403cae7019f0300000c0100000c800e0080"
                    + "03000008030000020000000805000000";

    private static final int CURRENT_CHILD_SA_SPI_IN = 0x2ad4c0a2;
    private static final int CURRENT_CHILD_SA_SPI_OUT = 0xcae7019f;

    private static final String IKE_SK_D_HEX_STRING = "C86B56EFCF684DCC2877578AEF3137167FE0EBF6";
    private static final byte[] SK_D = TestUtils.hexStringToByteArray(IKE_SK_D_HEX_STRING);

    private static final int KEY_LEN_IKE_SKD = 20;

    private IkeMacPrf mIkePrf;

    private Context mContext;
    private IpSecService mMockIpSecService;
    private IpSecManager mMockIpSecManager;
    private UdpEncapsulationSocket mMockUdpEncapSocket;

    private TestLooper mLooper;
    private ChildSessionStateMachine mChildSessionStateMachine;

    private List<IkePayload> mFirstSaReqPayloads = new LinkedList<>();
    private List<IkePayload> mFirstSaRespPayloads = new LinkedList<>();

    private ChildSaRecord mSpyCurrentChildSaRecord;

    private ISaRecordHelper mMockSaRecordHelper;

    private ChildSessionOptions mChildSessionOptions;
    private EncryptionTransform mChildEncryptionTransform;
    private IntegrityTransform mChildIntegrityTransform;
    private DhGroupTransform mChildDhGroupTransform;

    private SaProposal mMockNegotiatedProposal;

    private Handler mUserCbHandler;
    private IChildSessionCallback mMockChildSessionCallback;
    private IChildSessionSmCallback mMockChildSessionSmCallback;

    private ArgumentCaptor<ChildSaRecordConfig> mChildSaRecordConfigCaptor =
            ArgumentCaptor.forClass(ChildSaRecordConfig.class);
    private ArgumentCaptor<List<IkePayload>> mPayloadListCaptor =
            ArgumentCaptor.forClass(List.class);

    public ChildSessionStateMachineTest() {
        mMockSaRecordHelper = mock(SaRecord.ISaRecordHelper.class);
        mMockChildSessionSmCallback = mock(IChildSessionSmCallback.class);

        mChildEncryptionTransform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128);
        mChildIntegrityTransform =
                new IntegrityTransform(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96);

        mChildDhGroupTransform = new DhGroupTransform(SaProposal.DH_GROUP_1024_BIT_MODP);
    }

    @Before
    public void setup() throws Exception {
        if (Looper.myLooper() == null) Looper.prepare();

        mIkePrf =
                IkeMacPrf.create(
                        new PrfTransform(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1),
                        IkeMessage.getSecurityProvider());

        mContext = InstrumentationRegistry.getContext();
        mMockIpSecService = mock(IpSecService.class);
        mMockIpSecManager = new IpSecManager(mContext, mMockIpSecService);
        mMockUdpEncapSocket = mock(UdpEncapsulationSocket.class);

        mMockNegotiatedProposal = mock(SaProposal.class);

        mUserCbHandler = new Handler();
        mMockChildSessionCallback = mock(IChildSessionCallback.class);
        mChildSessionOptions = buildChildSessionOptions();

        // Setup thread and looper
        mLooper = new TestLooper();
        mChildSessionStateMachine =
                new ChildSessionStateMachine(
                        mLooper.getLooper(),
                        mContext,
                        mMockIpSecManager,
                        mChildSessionOptions,
                        mUserCbHandler,
                        mMockChildSessionCallback,
                        mMockChildSessionSmCallback);
        mChildSessionStateMachine.setDbg(true);
        SaRecord.setSaRecordHelper(mMockSaRecordHelper);

        setUpFirstSaNegoPayloadLists();
        setUpChildSaRecords();

        mChildSessionStateMachine.start();
    }

    @After
    public void tearDown() {
        mChildSessionStateMachine.setDbg(false);
        SaRecord.setSaRecordHelper(new SaRecordHelper());
    }

    private SaProposal buildSaProposal() throws Exception {
        return SaProposal.Builder.newChildSaProposalBuilder()
                .addEncryptionAlgorithm(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128)
                .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                .build();
    }

    private ChildSessionOptions buildChildSessionOptions() throws Exception {
        return new ChildSessionOptions.Builder().addSaProposal(buildSaProposal()).build();
    }

    private void setUpChildSaRecords() {
        mSpyCurrentChildSaRecord =
                makeSpyChildSaRecord(CURRENT_CHILD_SA_SPI_IN, CURRENT_CHILD_SA_SPI_OUT);
    }

    private void setUpFirstSaNegoPayloadLists() throws Exception {
        // Build locally generated SA payload that has its SPI resource allocated.
        when(mMockIpSecService.allocateSecurityParameterIndex(
                        eq(LOCAL_ADDRESS.getHostAddress()), anyInt(), anyObject()))
                .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(CURRENT_CHILD_SA_SPI_IN));
        IkeSaPayload reqSaPayload =
                IkeSaPayload.createChildSaRequestPayload(
                        mChildSessionOptions.getSaProposals(), mMockIpSecManager, LOCAL_ADDRESS);
        mFirstSaReqPayloads.add(reqSaPayload);

        // Build a remotely generated SA payload whoes SPI resource has not been allocated.
        when(mMockIpSecService.allocateSecurityParameterIndex(
                        eq(REMOTE_ADDRESS.getHostAddress()), anyInt(), anyObject()))
                .thenReturn(
                        MockIpSecTestUtils.buildDummyIpSecSpiResponse(CURRENT_CHILD_SA_SPI_OUT));
        IkeSaPayload respSaPayload =
                (IkeSaPayload)
                        (IkeTestUtils.hexStringToIkePayload(
                                IkePayload.PAYLOAD_TYPE_SA, true, IKE_AUTH_RESP_SA_PAYLOAD));
        mFirstSaRespPayloads.add(respSaPayload);

        // Build TS Payloads
        IkeTsPayload tsInitPayload =
                new IkeTsPayload(
                        true /*isInitiator*/, mChildSessionOptions.getLocalTrafficSelectors());
        IkeTsPayload tsRespPayload =
                new IkeTsPayload(
                        false /*isInitiator*/, mChildSessionOptions.getRemoteTrafficSelectors());

        mFirstSaReqPayloads.add(tsInitPayload);
        mFirstSaReqPayloads.add(tsRespPayload);
        mFirstSaRespPayloads.add(tsInitPayload);
        mFirstSaRespPayloads.add(tsRespPayload);

        // Build Nonce Payloads
        mFirstSaReqPayloads.add(new IkeNoncePayload());
        mFirstSaRespPayloads.add(new IkeNoncePayload());
    }

    private ChildSaRecord makeSpyChildSaRecord(int inboundSpi, int outboundSpi) {
        ChildSaRecord child =
                spy(
                        new ChildSaRecord(
                                inboundSpi,
                                outboundSpi,
                                true /*localInit*/,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null));
        doNothing().when(child).close();
        return child;
    }

    private void quitAndVerify() {
        reset(mMockChildSessionSmCallback);
        mChildSessionStateMachine.quit();
        mLooper.dispatchAll();

        verify(mMockChildSessionSmCallback).onProcedureFinished(mChildSessionStateMachine);
        verify(mMockChildSessionSmCallback).onChildSessionClosed(mMockChildSessionCallback);
    }

    private void verifyInitCreateChildResp(
            List<IkePayload> reqPayloads, List<IkePayload> respPayloads) throws Exception {
        verify(mMockChildSessionSmCallback)
                .onChildSaCreated(
                        mSpyCurrentChildSaRecord.getRemoteSpi(), mChildSessionStateMachine);
        verify(mMockChildSessionSmCallback).onProcedureFinished(mChildSessionStateMachine);
        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.Idle);

        // Validate negotiated SA proposal.
        SaProposal negotiatedProposal = mChildSessionStateMachine.mSaProposal;
        assertNotNull(negotiatedProposal);
        assertEquals(
                new EncryptionTransform[] {mChildEncryptionTransform},
                negotiatedProposal.getEncryptionTransforms());
        assertEquals(
                new IntegrityTransform[] {mChildIntegrityTransform},
                negotiatedProposal.getIntegrityTransforms());

        // Validate current ChildSaRecord
        verify(mMockSaRecordHelper)
                .makeChildSaRecord(
                        eq(reqPayloads), eq(respPayloads), mChildSaRecordConfigCaptor.capture());
        ChildSaRecordConfig childSaRecordConfig = mChildSaRecordConfigCaptor.getValue();

        assertEquals(mContext, childSaRecordConfig.context);
        assertEquals(CURRENT_CHILD_SA_SPI_IN, childSaRecordConfig.initSpi.getSpi());
        assertEquals(CURRENT_CHILD_SA_SPI_OUT, childSaRecordConfig.respSpi.getSpi());
        assertEquals(LOCAL_ADDRESS, childSaRecordConfig.initAddress);
        assertEquals(REMOTE_ADDRESS, childSaRecordConfig.respAddress);
        assertEquals(mMockUdpEncapSocket, childSaRecordConfig.udpEncapSocket);
        assertEquals(mIkePrf, childSaRecordConfig.ikePrf);
        assertArrayEquals(SK_D, childSaRecordConfig.skD);
        assertFalse(childSaRecordConfig.isTransport);
        assertTrue(childSaRecordConfig.isLocalInit);
        assertTrue(childSaRecordConfig.hasIntegrityAlgo);

        assertEquals(mSpyCurrentChildSaRecord, mChildSessionStateMachine.mCurrentChildSaRecord);

        verify(mMockChildSessionSmCallback)
                .onChildSaCreated(anyInt(), eq(mChildSessionStateMachine));
        verify(mMockChildSessionSmCallback).onProcedureFinished(mChildSessionStateMachine);
        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.Idle);
    }

    @Test
    public void testCreateFirstChild() throws Exception {
        when(mMockSaRecordHelper.makeChildSaRecord(any(), any(), any()))
                .thenReturn(mSpyCurrentChildSaRecord);

        mChildSessionStateMachine.handleFirstChildExchange(
                mFirstSaReqPayloads,
                mFirstSaRespPayloads,
                LOCAL_ADDRESS,
                REMOTE_ADDRESS,
                mMockUdpEncapSocket,
                mIkePrf,
                SK_D);
        mLooper.dispatchAll();

        verifyInitCreateChildResp(mFirstSaReqPayloads, mFirstSaRespPayloads);

        quitAndVerify();
    }

    private void verifyOutboundCreatePayloadTypes(List<IkePayload> outboundPayloads) {
        assertNotNull(
                IkePayload.getPayloadForTypeInProvidedList(
                        PAYLOAD_TYPE_SA, IkeSaPayload.class, outboundPayloads));
        assertNotNull(
                IkePayload.getPayloadForTypeInProvidedList(
                        PAYLOAD_TYPE_TS_INITIATOR, IkeTsPayload.class, outboundPayloads));
        assertNotNull(
                IkePayload.getPayloadForTypeInProvidedList(
                        PAYLOAD_TYPE_TS_RESPONDER, IkeTsPayload.class, outboundPayloads));
        assertNotNull(
                IkePayload.getPayloadForTypeInProvidedList(
                        PAYLOAD_TYPE_NONCE, IkeNoncePayload.class, outboundPayloads));
        assertNull(
                IkePayload.getPayloadForTypeInProvidedList(
                        PAYLOAD_TYPE_KE, IkeKePayload.class, outboundPayloads));
    }

    @Test
    public void testCreateChild() throws Exception {
        when(mMockSaRecordHelper.makeChildSaRecord(any(), any(), any()))
                .thenReturn(mSpyCurrentChildSaRecord);

        mChildSessionStateMachine.createChildSession(
                LOCAL_ADDRESS, REMOTE_ADDRESS, mMockUdpEncapSocket, mIkePrf, SK_D);
        mLooper.dispatchAll();

        // Validate outbound payload list
        verify(mMockChildSessionSmCallback)
                .onOutboundPayloadsReady(
                        eq(EXCHANGE_TYPE_CREATE_CHILD_SA),
                        eq(false),
                        mPayloadListCaptor.capture(),
                        eq(mChildSessionStateMachine));

        List<IkePayload> reqPayloadList = mPayloadListCaptor.getValue();
        verifyOutboundCreatePayloadTypes(reqPayloadList);
        assertTrue(
                IkePayload.getPayloadListForTypeInProvidedList(
                                PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class, reqPayloadList)
                        .isEmpty());

        mChildSessionStateMachine.receiveResponse(
                EXCHANGE_TYPE_CREATE_CHILD_SA, mFirstSaRespPayloads);
        mLooper.dispatchAll();

        verifyInitCreateChildResp(reqPayloadList, mFirstSaRespPayloads);

        quitAndVerify();
    }

    private void setupIdleStateMachine() throws Exception {
        mChildSessionStateMachine.mLocalAddress = LOCAL_ADDRESS;
        mChildSessionStateMachine.mRemoteAddress = REMOTE_ADDRESS;
        mChildSessionStateMachine.mUdpEncapSocket = mMockUdpEncapSocket;
        mChildSessionStateMachine.mIkePrf = mIkePrf;
        mChildSessionStateMachine.mSkD = SK_D;

        mChildSessionStateMachine.mSaProposal = buildSaProposal();
        mChildSessionStateMachine.mLocalTs = mChildSessionOptions.getLocalTrafficSelectors();
        mChildSessionStateMachine.mRemoteTs = mChildSessionOptions.getRemoteTrafficSelectors();

        mChildSessionStateMachine.mCurrentChildSaRecord = mSpyCurrentChildSaRecord;

        mChildSessionStateMachine.sendMessage(
                CMD_FORCE_TRANSITION, mChildSessionStateMachine.mIdle);
        mLooper.dispatchAll();

        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.Idle);
    }

    private List<IkePayload> makeDeletePayloads(int spi) {
        List<IkePayload> inboundPayloads = new ArrayList<>(1);
        inboundPayloads.add(new IkeDeletePayload(new int[] {spi}));
        return inboundPayloads;
    }

    @Test
    public void testDeleteChildLocal() throws Exception {
        setupIdleStateMachine();

        // Test initiating Delete request
        mChildSessionStateMachine.deleteChildSession();
        mLooper.dispatchAll();

        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.DeleteChildLocalDelete);
        verify(mMockChildSessionSmCallback)
                .onOutboundPayloadsReady(
                        eq(EXCHANGE_TYPE_INFORMATIONAL),
                        eq(false),
                        mPayloadListCaptor.capture(),
                        eq(mChildSessionStateMachine));

        List<IkePayload> reqPayloadList = mPayloadListCaptor.getValue();
        assertEquals(1, reqPayloadList.size());

        List<IkeDeletePayload> deletePayloads =
                IkePayload.getPayloadListForTypeInProvidedList(
                        PAYLOAD_TYPE_DELETE, IkeDeletePayload.class, reqPayloadList);
        assertEquals(1, deletePayloads.size());
        IkeDeletePayload deletePayload = deletePayloads.get(0);
        assertEquals(mSpyCurrentChildSaRecord.getLocalSpi(), deletePayload.spisToDelete[0]);

        // Test receiving Delete response
        mChildSessionStateMachine.receiveResponse(
                EXCHANGE_TYPE_INFORMATIONAL,
                makeDeletePayloads(mSpyCurrentChildSaRecord.getRemoteSpi()));
        mLooper.dispatchAll();

        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.Closed);
    }

    @Test
    public void testSimultaneousDeleteChild() throws Exception {
        setupIdleStateMachine();

        mChildSessionStateMachine.deleteChildSession();
        mChildSessionStateMachine.receiveRequest(
                IKE_EXCHANGE_SUBTYPE_DELETE_CHILD,
                makeDeletePayloads(mSpyCurrentChildSaRecord.getRemoteSpi()));
        mLooper.dispatchAll();

        verify(mMockChildSessionSmCallback)
                .onOutboundPayloadsReady(
                        eq(EXCHANGE_TYPE_INFORMATIONAL),
                        eq(true),
                        mPayloadListCaptor.capture(),
                        eq(mChildSessionStateMachine));
        List<IkePayload> respPayloadList = mPayloadListCaptor.getValue();
        assertTrue(respPayloadList.isEmpty());

        mChildSessionStateMachine.receiveResponse(EXCHANGE_TYPE_INFORMATIONAL, new LinkedList<>());
        mLooper.dispatchAll();

        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.Closed);
    }

    @Test
    public void testReplyRekeyRequestDuringDeletion() throws Exception {
        setupIdleStateMachine();

        mChildSessionStateMachine.deleteChildSession();
        mChildSessionStateMachine.receiveRequest(
                IKE_EXCHANGE_SUBTYPE_REKEY_CHILD, mock(List.class));
        mLooper.dispatchAll();

        // Verify outbound response to Rekey Child request
        verify(mMockChildSessionSmCallback)
                .onOutboundPayloadsReady(
                        eq(EXCHANGE_TYPE_INFORMATIONAL),
                        eq(true),
                        mPayloadListCaptor.capture(),
                        eq(mChildSessionStateMachine));
        List<IkePayload> respPayloadList = mPayloadListCaptor.getValue();
        assertEquals(1, respPayloadList.size());

        IkeNotifyPayload notifyPayload = (IkeNotifyPayload) respPayloadList.get(0);
        assertEquals(ERROR_TYPE_TEMPORARY_FAILURE, notifyPayload.notifyType);
        assertEquals(0, notifyPayload.notifyData.length);

        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.DeleteChildLocalDelete);
    }

    @Test
    public void testDeleteChildRemote() throws Exception {
        setupIdleStateMachine();

        mChildSessionStateMachine.receiveRequest(
                IKE_EXCHANGE_SUBTYPE_DELETE_CHILD,
                makeDeletePayloads(mSpyCurrentChildSaRecord.getRemoteSpi()));
        mLooper.dispatchAll();

        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.Closed);
        // Verify response
        verify(mMockChildSessionSmCallback)
                .onOutboundPayloadsReady(
                        eq(EXCHANGE_TYPE_INFORMATIONAL),
                        eq(true),
                        mPayloadListCaptor.capture(),
                        eq(mChildSessionStateMachine));
        List<IkePayload> respPayloadList = mPayloadListCaptor.getValue();

        assertEquals(1, respPayloadList.size());
        assertArrayEquals(
                new int[] {mSpyCurrentChildSaRecord.getLocalSpi()},
                ((IkeDeletePayload) respPayloadList.get(0)).spisToDelete);
    }

    @Test
    public void testRekeyChildLocalCreateSendsRequest() throws Exception {
        setupIdleStateMachine();

        // Send Rekey-Create request
        mChildSessionStateMachine.rekeyChildSession();
        mLooper.dispatchAll();
        assertTrue(
                mChildSessionStateMachine.getCurrentState()
                        instanceof ChildSessionStateMachine.RekeyChildLocalCreate);
        verify(mMockChildSessionSmCallback)
                .onOutboundPayloadsReady(
                        eq(EXCHANGE_TYPE_CREATE_CHILD_SA),
                        eq(false),
                        mPayloadListCaptor.capture(),
                        eq(mChildSessionStateMachine));

        // Verify outbound payload list
        List<IkePayload> reqPayloadList = mPayloadListCaptor.getValue();
        verifyOutboundCreatePayloadTypes(reqPayloadList);

        // Verify SA Payload
        IkeSaPayload saPayload =
                IkePayload.getPayloadForTypeInProvidedList(
                        PAYLOAD_TYPE_SA, IkeSaPayload.class, reqPayloadList);
        assertFalse(saPayload.isSaResponse);
        assertEquals(1, saPayload.proposalList.size());

        IkeSaPayload.ChildProposal proposal =
                (IkeSaPayload.ChildProposal) saPayload.proposalList.get(0);
        assertEquals(1, proposal.number); // Must be 1-indexed
        assertEquals(mChildSessionStateMachine.mSaProposal, proposal.saProposal);

        // Verify Notify-Rekey Payload
        List<IkeNotifyPayload> notifyPayloads =
                IkePayload.getPayloadListForTypeInProvidedList(
                        PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class, reqPayloadList);
        assertEquals(1, notifyPayloads.size());
        IkeNotifyPayload notifyPayload = notifyPayloads.get(0);
        assertEquals(NOTIFY_TYPE_REKEY_SA, notifyPayload.notifyType);
        assertEquals(PROTOCOL_ID_ESP, notifyPayload.protocolId);
        assertEquals(mSpyCurrentChildSaRecord.getLocalSpi(), notifyPayload.spi);
    }

    @Test
    public void testValidateExpectKeExistCase() throws Exception {
        when(mMockNegotiatedProposal.getDhGroupTransforms())
                .thenReturn(new DhGroupTransform[] {mChildDhGroupTransform});
        List<IkePayload> payloadList = new LinkedList<>();
        payloadList.add(new IkeKePayload(SaProposal.DH_GROUP_1024_BIT_MODP));

        CreateChildSaHelper.validateKePayloads(
                payloadList, true /*isResp*/, mMockNegotiatedProposal);
        CreateChildSaHelper.validateKePayloads(
                payloadList, false /*isResp*/, mMockNegotiatedProposal);
    }

    @Test
    public void testValidateExpectNoKeExistCase() throws Exception {
        when(mMockNegotiatedProposal.getDhGroupTransforms()).thenReturn(new DhGroupTransform[0]);
        List<IkePayload> payloadList = new LinkedList<>();

        CreateChildSaHelper.validateKePayloads(
                payloadList, true /*isResp*/, mMockNegotiatedProposal);
        CreateChildSaHelper.validateKePayloads(
                payloadList, false /*isResp*/, mMockNegotiatedProposal);
    }

    @Test
    public void testThrowWhenKeMissing() throws Exception {
        when(mMockNegotiatedProposal.getDhGroupTransforms())
                .thenReturn(new DhGroupTransform[] {mChildDhGroupTransform});
        List<IkePayload> payloadList = new LinkedList<>();

        try {
            CreateChildSaHelper.validateKePayloads(
                    payloadList, true /*isResp*/, mMockNegotiatedProposal);
            fail("Expected to fail due to the absence of KE Payload");
        } catch (InvalidSyntaxException expected) {
        }

        try {
            CreateChildSaHelper.validateKePayloads(
                    payloadList, false /*isResp*/, mMockNegotiatedProposal);
            fail("Expected to fail due to the absence of KE Payload");
        } catch (InvalidKeException expected) {
        }
    }

    @Test
    public void testThrowWhenKeHasMismatchedDhGroup() throws Exception {
        when(mMockNegotiatedProposal.getDhGroupTransforms())
                .thenReturn(new DhGroupTransform[] {mChildDhGroupTransform});
        List<IkePayload> payloadList = new LinkedList<>();
        payloadList.add(new IkeKePayload(SaProposal.DH_GROUP_2048_BIT_MODP));

        try {
            CreateChildSaHelper.validateKePayloads(
                    payloadList, true /*isResp*/, mMockNegotiatedProposal);
            fail("Expected to fail due to mismatched DH Group");
        } catch (InvalidSyntaxException expected) {
        }

        try {
            CreateChildSaHelper.validateKePayloads(
                    payloadList, false /*isResp*/, mMockNegotiatedProposal);
            fail("Expected to fail due to mismatched DH Group");
        } catch (InvalidKeException expected) {
        }
    }

    @Test
    public void testThrowForUnexpectedKe() throws Exception {
        DhGroupTransform noneGroup = new DhGroupTransform(SaProposal.DH_GROUP_NONE);
        when(mMockNegotiatedProposal.getDhGroupTransforms())
                .thenReturn(new DhGroupTransform[] {noneGroup});
        List<IkePayload> payloadList = new LinkedList<>();
        payloadList.add(new IkeKePayload(SaProposal.DH_GROUP_2048_BIT_MODP));

        try {
            CreateChildSaHelper.validateKePayloads(
                    payloadList, true /*isResp*/, mMockNegotiatedProposal);
            fail("Expected to fail due to unexpected KE payload.");
        } catch (InvalidSyntaxException expected) {
        }

        CreateChildSaHelper.validateKePayloads(
                payloadList, false /*isResp*/, mMockNegotiatedProposal);
    }
}
