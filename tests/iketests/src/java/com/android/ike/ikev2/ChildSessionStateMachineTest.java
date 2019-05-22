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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
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
import android.os.test.TestLooper;

import androidx.test.InstrumentationRegistry;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.IkeSessionStateMachine.IChildSessionSmCallback;
import com.android.ike.ikev2.SaRecord.ChildSaRecord;
import com.android.ike.ikev2.SaRecord.ChildSaRecordConfig;
import com.android.ike.ikev2.SaRecord.ISaRecordHelper;
import com.android.ike.ikev2.SaRecord.SaRecordHelper;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload;
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

    private TestLooper mLooper;
    private ChildSessionStateMachine mChildSessionStateMachine;

    private List<IkePayload> mFirstSaReqPayloads = new LinkedList<>();
    private List<IkePayload> mFirstSaRespPayloads = new LinkedList<>();

    private ChildSaRecord mSpyCurrentChildSaRecord;

    private ISaRecordHelper mMockSaRecordHelper;
    private IChildSessionSmCallback mMockChildSessionSmCallback;

    private ChildSessionOptions mChildSessionOptions;
    private EncryptionTransform mChildEncryptionTransform;
    private IntegrityTransform mChildIntegrityTransform;

    private ArgumentCaptor<ChildSaRecordConfig> mChildSaRecordConfigCaptor =
            ArgumentCaptor.forClass(ChildSaRecordConfig.class);

    public ChildSessionStateMachineTest() {
        mMockSaRecordHelper = mock(SaRecord.ISaRecordHelper.class);
        mMockChildSessionSmCallback = mock(IChildSessionSmCallback.class);

        mChildEncryptionTransform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128);
        mChildIntegrityTransform =
                new IntegrityTransform(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96);
    }

    @Before
    public void setup() throws Exception {
        mIkePrf =
                IkeMacPrf.create(
                        new PrfTransform(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1),
                        IkeMessage.getSecurityProvider());

        mContext = InstrumentationRegistry.getContext();
        mMockIpSecService = mock(IpSecService.class);
        mMockIpSecManager = new IpSecManager(mContext, mMockIpSecService);

        mChildSessionOptions = buildChildSessionOptions();

        // Setup thread and looper
        mLooper = new TestLooper();
        mChildSessionStateMachine =
                new ChildSessionStateMachine(
                        "ChildSessionStateMachine",
                        mLooper.getLooper(),
                        mContext,
                        mMockIpSecManager,
                        mChildSessionOptions,
                        LOCAL_ADDRESS,
                        REMOTE_ADDRESS,
                        mIkePrf,
                        SK_D);
        mChildSessionStateMachine.setDbg(true);
        SaRecord.setSaRecordHelper(mMockSaRecordHelper);

        setUpFirstSaNegoPayloadLists();
        setUpChildSaRecords();

        mChildSessionStateMachine.start();
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

    private void setUpChildSaRecords() {
        mSpyCurrentChildSaRecord =
                spy(makeDummyChildSaRecord(CURRENT_CHILD_SA_SPI_IN, CURRENT_CHILD_SA_SPI_OUT));
    }

    private void setUpFirstSaNegoPayloadLists() throws Exception {
        // Build locally generated SA payload that has its SPI resource allocated.
        when(mMockIpSecService.allocateSecurityParameterIndex(
                        eq(LOCAL_ADDRESS.getHostAddress()), anyInt(), anyObject()))
                .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(CURRENT_CHILD_SA_SPI_IN));
        IkeSaPayload reqSaPayload =
                IkeSaPayload.createChildSaPayload(
                        false /*isResp*/,
                        mChildSessionOptions.getSaProposals(),
                        mMockIpSecManager,
                        LOCAL_ADDRESS);
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

    private ChildSaRecord makeDummyChildSaRecord(int inboundSpi, int outboundSpi) {
        return new ChildSaRecord(
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
                null);
    }

    @After
    public void tearDown() {
        mChildSessionStateMachine.quit();
        mChildSessionStateMachine.setDbg(false);

        SaRecord.setSaRecordHelper(new SaRecordHelper());
    }

    @Test
    public void testCreateFirstChild() throws Exception {
        when(mMockSaRecordHelper.makeChildSaRecord(any(), any(), any()))
                .thenReturn(mSpyCurrentChildSaRecord);

        mChildSessionStateMachine.handleFirstChildExchange(
                mFirstSaReqPayloads, mFirstSaRespPayloads, mMockChildSessionSmCallback);
        mLooper.dispatchAll();

        verify(mMockChildSessionSmCallback)
                .onCreateChildSa(
                        mSpyCurrentChildSaRecord.getRemoteSpi(), mChildSessionStateMachine);
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
                        eq(mFirstSaReqPayloads),
                        eq(mFirstSaRespPayloads),
                        mChildSaRecordConfigCaptor.capture());
        ChildSaRecordConfig childSaRecordConfig = mChildSaRecordConfigCaptor.getValue();

        assertEquals(mContext, childSaRecordConfig.context);
        assertEquals(CURRENT_CHILD_SA_SPI_IN, childSaRecordConfig.initSpi.getSpi());
        assertEquals(CURRENT_CHILD_SA_SPI_OUT, childSaRecordConfig.respSpi.getSpi());
        assertEquals(LOCAL_ADDRESS, childSaRecordConfig.initAddress);
        assertEquals(REMOTE_ADDRESS, childSaRecordConfig.respAddress);
        assertEquals(mIkePrf, childSaRecordConfig.ikePrf);
        assertArrayEquals(SK_D, childSaRecordConfig.skD);
        assertFalse(childSaRecordConfig.isTransport);
        assertTrue(childSaRecordConfig.isLocalInit);
        assertTrue(childSaRecordConfig.hasIntegrityAlgo);

        assertEquals(mSpyCurrentChildSaRecord, mChildSessionStateMachine.mCurrentChildSaRecord);
    }
}
