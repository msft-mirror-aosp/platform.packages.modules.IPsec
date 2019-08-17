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

import static com.android.ike.ikev2.IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE;
import static com.android.ike.ikev2.IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET;
import static com.android.ike.ikev2.IkeSessionStateMachine.IKE_EXCHANGE_SUBTYPE_DELETE_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.IKE_EXCHANGE_SUBTYPE_REKEY_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.SA_SOFT_LIFETIME_MS;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_CHILD_SA_NOT_FOUND;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_SYNTAX;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_NO_ADDITIONAL_SAS;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_INFORMATIONAL;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_OK;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.argThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Looper;
import android.os.test.TestLooper;
import android.telephony.TelephonyManager;

import com.android.ike.TestUtils;
import com.android.ike.eap.EapAuthenticator;
import com.android.ike.eap.EapSessionConfig;
import com.android.ike.eap.IEapCallback;
import com.android.ike.ikev2.ChildSessionStateMachine.IChildSessionSmCallback;
import com.android.ike.ikev2.ChildSessionStateMachineFactory.ChildSessionFactoryHelper;
import com.android.ike.ikev2.ChildSessionStateMachineFactory.IChildSessionFactoryHelper;
import com.android.ike.ikev2.IkeIdentification.IkeIpv4AddrIdentification;
import com.android.ike.ikev2.IkeLocalRequestScheduler.ChildLocalRequest;
import com.android.ike.ikev2.IkeLocalRequestScheduler.LocalRequest;
import com.android.ike.ikev2.IkeSessionStateMachine.IkeSecurityParameterIndex;
import com.android.ike.ikev2.IkeSessionStateMachine.ReceivedIkePacket;
import com.android.ike.ikev2.SaRecord.ISaRecordHelper;
import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.SaRecord.IkeSaRecordConfig;
import com.android.ike.ikev2.SaRecord.SaRecordHelper;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.exceptions.AuthenticationFailedException;
import com.android.ike.ikev2.exceptions.IkeInternalException;
import com.android.ike.ikev2.exceptions.IkeProtocolException;
import com.android.ike.ikev2.exceptions.NoValidProposalChosenException;
import com.android.ike.ikev2.message.IkeAuthDigitalSignPayload;
import com.android.ike.ikev2.message.IkeAuthPayload;
import com.android.ike.ikev2.message.IkeAuthPskPayload;
import com.android.ike.ikev2.message.IkeDeletePayload;
import com.android.ike.ikev2.message.IkeEapPayload;
import com.android.ike.ikev2.message.IkeHeader;
import com.android.ike.ikev2.message.IkeIdPayload;
import com.android.ike.ikev2.message.IkeInformationalPayload;
import com.android.ike.ikev2.message.IkeKePayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeMessage.DecodeResult;
import com.android.ike.ikev2.message.IkeMessage.IIkeMessageHelper;
import com.android.ike.ikev2.message.IkeMessage.IkeMessageHelper;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkeNotifyPayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload;
import com.android.ike.ikev2.message.IkeSaPayload.DhGroupTransform;
import com.android.ike.ikev2.message.IkeSaPayload.EncryptionTransform;
import com.android.ike.ikev2.message.IkeSaPayload.EsnTransform;
import com.android.ike.ikev2.message.IkeSaPayload.IntegrityTransform;
import com.android.ike.ikev2.message.IkeSaPayload.PrfTransform;
import com.android.ike.ikev2.message.IkeTestUtils;
import com.android.ike.ikev2.message.IkeTsPayload;
import com.android.internal.util.State;

import libcore.net.InetAddressUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.Inet4Address;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executor;

public final class IkeSessionStateMachineTest {
    private static final Inet4Address LOCAL_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("192.0.2.200"));
    private static final Inet4Address REMOTE_ADDRESS =
            (Inet4Address) (InetAddressUtils.parseNumericAddress("127.0.0.1"));

    private static final String IKE_INIT_RESP_HEX_STRING =
            "5f54bf6d8b48e6e1909232b3d1edcb5c21202220000000000000014c220000300000"
                    + "002c010100040300000c0100000c800e008003000008030000020300000802000002"
                    + "00000008040000022800008800020000fe014fefed55a4229928bfa3dad1ea6ffaca"
                    + "abfb5f5bdd71790e99a192530e3f849d3a3d96dc6e0a7a10ff6f72a6162103ac573c"
                    + "acd41d08b7a034cad8f5eab09c14ced5a9e4af5692dff028f21c1119dd75226b6af6"
                    + "b2f009245369c9892cc5742e5c94a254ebff052470771fb2cb4f29a35d8953e18a1a"
                    + "6c6fbc56acc188a5290000249756112ca539f5c25abacc7ee92b73091942a9c06950"
                    + "f98848f1af1694c4ddff2900001c00004004c53f054b976a25d75fde72dbf1c7b6c8"
                    + "c9aa9ca12900001c00004005b16d79b21c1bc89ca7350f42de805be0227e2ed62b00"
                    + "00080000401400000014882fe56d6fd20dbc2251613b2ebe5beb";
    private static final String IKE_SA_PAYLOAD_HEX_STRING =
            "220000300000002c010100040300000c0100000c800e00800300000803000002030"
                    + "00008020000020000000804000002";
    private static final String IKE_REKEY_SA_PAYLOAD_HEX_STRING =
            "22000038000000340101080400000000000000FF0300000c0100000c800e0080030"
                    + "000080300000203000008020000020000000804000002";
    private static final int IKE_REKEY_SA_INITIATOR_SPI = 0xff;
    private static final String KE_PAYLOAD_HEX_STRING =
            "2800008800020000b4a2faf4bb54878ae21d638512ece55d9236fc50"
                    + "46ab6cef82220f421f3ce6361faf36564ecb6d28798a94aa"
                    + "d7b2b4b603ddeaaa5630adb9ece8ac37534036040610ebdd"
                    + "92f46bef84f0be7db860351843858f8acf87056e272377f7"
                    + "0c9f2d81e29c7b0ce4f291a3a72476bb0b278fd4b7b0a4c2"
                    + "6bbeb08214c7071376079587";
    private static final String NONCE_INIT_PAYLOAD_HEX_STRING =
            "29000024c39b7f368f4681b89fa9b7be6465abd7c5f68b6ed5d3b4c72cb4240eb5c46412";
    private static final String NONCE_RESP_PAYLOAD_HEX_STRING =
            "290000249756112ca539f5c25abacc7ee92b73091942a9c06950f98848f1af1694c4ddff";
    private static final String NONCE_INIT_HEX_STRING =
            "c39b7f368f4681b89fa9b7be6465abd7c5f68b6ed5d3b4c72cb4240eb5c46412";
    private static final String NONCE_RESP_HEX_STRING =
            "9756112ca539f5c25abacc7ee92b73091942a9c06950f98848f1af1694c4ddff";
    private static final String NAT_DETECTION_SOURCE_PAYLOAD_HEX_STRING =
            "2900001c00004004e54f73b7d83f6beb881eab2051d8663f421d10b0";
    private static final String NAT_DETECTION_DESTINATION_PAYLOAD_HEX_STRING =
            "2b00001c00004005d915368ca036004cb578ae3e3fb268509aeab190";
    private static final String DELETE_IKE_PAYLOAD_HEX_STRING = "0000000801000000";
    private static final String NOTIFY_REKEY_IKE_PAYLOAD_HEX_STRING = "2100000800004009";
    private static final String ID_PAYLOAD_INITIATOR_HEX_STRING =
            "290000180200000031313233343536373839414243444546";
    private static final String ID_PAYLOAD_RESPONDER_HEX_STRING = "2700000c010000007f000001";
    private static final String PSK_AUTH_RESP_PAYLOAD_HEX_STRING =
            "2100001c0200000058f36412e9b7b38df817a9f7779b7a008dacdd25";
    private static final String GENERIC_DIGITAL_SIGN_AUTH_RESP_HEX_STRING =
            "300000580e0000000f300d06092a864886f70d01010b05006f76af4150d653c5d413"
                    + "6b9f69d905849bf075c563e6d14ccda42361ec3e7d12c72e2dece5711ea1d952f7b8e"
                    + "12c5d982aa4efdaeac36a02b222aa96242cc424";
    private static final String CHILD_SA_PAYLOAD_HEX_STRING =
            "2c00002c0000002801030403cae7019f0300000c0100000c800e008003000008030"
                    + "000020000000805000000";
    private static final String TS_INIT_PAYLOAD_HEX_STRING =
            "2d00001801000000070000100000ffff00000000ffffffff";
    private static final String TS_RESP_PAYLOAD_HEX_STRING =
            "2900001801000000070000100000ffff000000000fffffff";

    private static final String PSK_HEX_STRING = "6A756E69706572313233";

    private static final String PRF_KEY_INIT_HEX_STRING =
            "094787780EE466E2CB049FA327B43908BC57E485";
    private static final String PRF_KEY_RESP_HEX_STRING =
            "A30E6B08BE56C0E6BFF4744143C75219299E1BEB";

    private static final byte[] EAP_DUMMY_MSG = "EAP Message".getBytes();

    private static final int KEY_LEN_IKE_INTE = 20;
    private static final int KEY_LEN_IKE_ENCR = 16;
    private static final int KEY_LEN_IKE_PRF = 20;
    private static final int KEY_LEN_IKE_SKD = KEY_LEN_IKE_PRF;

    private static final int CHILD_SPI_LOCAL = 0x2ad4c0a2;
    private static final int CHILD_SPI_REMOTE = 0xcae7019f;

    private static final int DUMMY_UDP_ENCAP_RESOURCE_ID = 0x3234;
    private static final int UDP_ENCAP_PORT = 34567;

    private static final int EAP_SIM_SUB_ID = 1;

    private MockIpSecTestUtils mMockIpSecTestUtils;
    private Context mContext;
    private IpSecManager mIpSecManager;
    private UdpEncapsulationSocket mUdpEncapSocket;

    private IkeSocket mSpyIkeSocket;

    private TestLooper mLooper;
    private IkeSessionStateMachine mIkeSessionStateMachine;

    private byte[] mPsk;

    private ChildSessionOptions mChildSessionOptions;

    private Executor mSpyUserCbExecutor;
    private IIkeSessionCallback mMockIkeSessionCallback;
    private IChildSessionCallback mMockChildSessionCallback;

    private EncryptionTransform mIkeEncryptionTransform;
    private IntegrityTransform mIkeIntegrityTransform;
    private PrfTransform mIkePrfTransform;
    private DhGroupTransform mIkeDhGroupTransform;

    private IIkeMessageHelper mMockIkeMessageHelper;
    private ISaRecordHelper mMockSaRecordHelper;

    private ChildSessionStateMachine mMockChildSessionStateMachine;
    private IChildSessionFactoryHelper mMockChildSessionFactoryHelper;
    private IChildSessionSmCallback mDummyChildSmCallback;

    private IkeSaRecord mSpyCurrentIkeSaRecord;
    private IkeSaRecord mSpyLocalInitIkeSaRecord;
    private IkeSaRecord mSpyRemoteInitIkeSaRecord;

    private int mExpectedCurrentSaLocalReqMsgId;
    private int mExpectedCurrentSaRemoteReqMsgId;

    private EapSessionConfig mEapSessionConfig;
    private IkeEapAuthenticatorFactory mMockEapAuthenticatorFactory;
    private EapAuthenticator mMockEapAuthenticator;

    private ArgumentCaptor<IkeMessage> mIkeMessageCaptor =
            ArgumentCaptor.forClass(IkeMessage.class);
    private ArgumentCaptor<IkeSaRecordConfig> mIkeSaRecordConfigCaptor =
            ArgumentCaptor.forClass(IkeSaRecordConfig.class);
    private ArgumentCaptor<IChildSessionSmCallback> mChildSessionSmCbCaptor =
            ArgumentCaptor.forClass(IChildSessionSmCallback.class);
    private ArgumentCaptor<List<IkePayload>> mPayloadListCaptor =
            ArgumentCaptor.forClass(List.class);

    private ReceivedIkePacket makeDummyReceivedIkeInitRespPacket(
            long initiatorSpi,
            long responderSpi,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            boolean fromIkeInit,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {

        List<IkePayload> payloadList =
                hexStrListToIkePayloadList(payloadTypeList, payloadHexStringList, isResp);
        // Build a remotely generated NAT_DETECTION_SOURCE_IP payload to mock a remote node's
        // network that is not behind NAT.
        IkePayload sourceNatPayload =
                new IkeNotifyPayload(
                        NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP,
                        IkeNotifyPayload.generateNatDetectionData(
                                initiatorSpi,
                                responderSpi,
                                REMOTE_ADDRESS,
                                IkeSocket.IKE_SERVER_PORT));
        payloadList.add(sourceNatPayload);
        return makeDummyUnencryptedReceivedIkePacket(
                initiatorSpi, responderSpi, eType, isResp, fromIkeInit, payloadList);
    }

    private ReceivedIkePacket makeDummyUnencryptedReceivedIkePacket(
            long initiatorSpi,
            long responderSpi,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            boolean fromIkeInit,
            List<IkePayload> payloadList)
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
                        payloadList);

        byte[] dummyIkePacketBytes = new byte[0];
        when(mMockIkeMessageHelper.decode(0, dummyIkeMessage.ikeHeader, dummyIkePacketBytes))
                .thenReturn(new DecodeResult(DECODE_STATUS_OK, dummyIkeMessage, null));

        return new ReceivedIkePacket(dummyIkeMessage.ikeHeader, dummyIkePacketBytes);
    }

    private ReceivedIkePacket makeDummyEncryptedReceivedIkePacket(
            IkeSaRecord ikeSaRecord,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            List<Integer> payloadTypeList,
            List<String> payloadHexStringList)
            throws Exception {
        List<IkePayload> payloadList =
                hexStrListToIkePayloadList(payloadTypeList, payloadHexStringList, isResp);
        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                ikeSaRecord, eType, isResp, payloadList);
    }

    private ReceivedIkePacket makeDummyEncryptedReceivedIkePacketWithPayloadList(
            IkeSaRecord ikeSaRecord,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            List<IkePayload> payloadList)
            throws Exception {
        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                ikeSaRecord,
                eType,
                isResp,
                isResp
                        ? ikeSaRecord.getLocalRequestMessageId()
                        : ikeSaRecord.getRemoteRequestMessageId(),
                payloadList,
                new byte[0] /*dummyIkePacketBytes*/);
    }

    private ReceivedIkePacket makeDummyEncryptedReceivedIkePacketWithPayloadList(
            IkeSaRecord ikeSaRecord,
            @IkeHeader.ExchangeType int eType,
            boolean isResp,
            int msgId,
            List<IkePayload> payloadList,
            byte[] dummyIkePacketBytes)
            throws Exception {
        boolean fromIkeInit = !ikeSaRecord.isLocalInit;
        IkeMessage dummyIkeMessage =
                makeDummyIkeMessageForTest(
                        ikeSaRecord.getInitiatorSpi(),
                        ikeSaRecord.getResponderSpi(),
                        eType,
                        isResp,
                        fromIkeInit,
                        msgId,
                        true /*isEncyprted*/,
                        payloadList);

        when(mMockIkeMessageHelper.decode(
                        anyInt(),
                        any(),
                        any(),
                        eq(ikeSaRecord),
                        eq(dummyIkeMessage.ikeHeader),
                        eq(dummyIkePacketBytes)))
                .thenReturn(new DecodeResult(DECODE_STATUS_OK, dummyIkeMessage, null));

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
            List<IkePayload> payloadList)
            throws Exception {
        int firstPayloadType =
                isEncrypted ? IkePayload.PAYLOAD_TYPE_SK : IkePayload.PAYLOAD_TYPE_NO_NEXT;

        IkeHeader header =
                new IkeHeader(
                        initSpi, respSpi, firstPayloadType, eType, isResp, fromikeInit, messageId);

        return new IkeMessage(header, payloadList);
    }

    private static List<IkePayload> hexStrListToIkePayloadList(
            List<Integer> payloadTypeList, List<String> payloadHexStringList, boolean isResp)
            throws Exception {
        List<IkePayload> payloadList = new LinkedList<>();
        for (int i = 0; i < payloadTypeList.size(); i++) {
            payloadList.add(
                    IkeTestUtils.hexStringToIkePayload(
                            payloadTypeList.get(i), isResp, payloadHexStringList.get(i)));
        }
        return payloadList;
    }

    private void verifyDecodeEncryptedMessage(IkeSaRecord record, ReceivedIkePacket rcvPacket)
            throws Exception {
        verify(mMockIkeMessageHelper)
                .decode(
                        anyInt(),
                        any(),
                        any(),
                        eq(record),
                        eq(rcvPacket.ikeHeader),
                        eq(rcvPacket.ikePacketBytes));
    }

    private static IkeSaRecord makeDummyIkeSaRecord(long initSpi, long respSpi, boolean isLocalInit)
            throws IOException {
        Inet4Address initAddress = isLocalInit ? LOCAL_ADDRESS : REMOTE_ADDRESS;
        Inet4Address respAddress = isLocalInit ? REMOTE_ADDRESS : LOCAL_ADDRESS;

        return new IkeSaRecord(
                IkeSecurityParameterIndex.allocateSecurityParameterIndex(initAddress, initSpi),
                IkeSecurityParameterIndex.allocateSecurityParameterIndex(respAddress, respSpi),
                isLocalInit,
                TestUtils.hexStringToByteArray(NONCE_INIT_HEX_STRING),
                TestUtils.hexStringToByteArray(NONCE_RESP_HEX_STRING),
                new byte[KEY_LEN_IKE_SKD],
                new byte[KEY_LEN_IKE_INTE],
                new byte[KEY_LEN_IKE_INTE],
                new byte[KEY_LEN_IKE_ENCR],
                new byte[KEY_LEN_IKE_ENCR],
                TestUtils.hexStringToByteArray(PRF_KEY_INIT_HEX_STRING),
                TestUtils.hexStringToByteArray(PRF_KEY_RESP_HEX_STRING),
                new LocalRequest(CMD_LOCAL_REQUEST_REKEY_IKE));
    }

    @Before
    public void setUp() throws Exception {
        if (Looper.myLooper() == null) Looper.prepare();

        mMockIpSecTestUtils = MockIpSecTestUtils.setUpMockIpSec();
        mIpSecManager = mMockIpSecTestUtils.getIpSecManager();
        mContext = mMockIpSecTestUtils.getContext();
        mUdpEncapSocket = mIpSecManager.openUdpEncapsulationSocket();
        mEapSessionConfig = new EapSessionConfig.Builder()
                .setEapSimConfig(EAP_SIM_SUB_ID, TelephonyManager.APPTYPE_USIM)
                .build();

        mMockEapAuthenticatorFactory = mock(IkeEapAuthenticatorFactory.class);
        mMockEapAuthenticator = mock(EapAuthenticator.class);
        when(mMockEapAuthenticatorFactory.newEapAuthenticator(any(), any(), any(), any()))
                .thenReturn(mMockEapAuthenticator);

        mPsk = TestUtils.hexStringToByteArray(PSK_HEX_STRING);

        mChildSessionOptions = buildChildSessionOptions();

        mIkeEncryptionTransform =
                new EncryptionTransform(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128);
        mIkeIntegrityTransform =
                new IntegrityTransform(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96);
        mIkePrfTransform = new PrfTransform(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1);
        mIkeDhGroupTransform = new DhGroupTransform(SaProposal.DH_GROUP_1024_BIT_MODP);

        mSpyUserCbExecutor =
                spy(
                        (command) -> {
                            command.run();
                        });

        mMockIkeSessionCallback = mock(IIkeSessionCallback.class);
        mMockChildSessionCallback = mock(IChildSessionCallback.class);

        mLooper = new TestLooper();

        mMockChildSessionStateMachine = mock(ChildSessionStateMachine.class);
        mMockChildSessionFactoryHelper = mock(IChildSessionFactoryHelper.class);
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                mMockChildSessionFactoryHelper);
        setupChildStateMachineFactory(mMockChildSessionStateMachine);

        // Setup state machine
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsPsk(mPsk));

        mMockIkeMessageHelper = mock(IkeMessage.IIkeMessageHelper.class);
        when(mMockIkeMessageHelper.encode(any())).thenReturn(new byte[0]);
        when(mMockIkeMessageHelper.encryptAndEncode(any(), any(), any(), any()))
                .thenReturn(new byte[0]);
        IkeMessage.setIkeMessageHelper(mMockIkeMessageHelper);

        mMockSaRecordHelper = mock(SaRecord.ISaRecordHelper.class);
        SaRecord.setSaRecordHelper(mMockSaRecordHelper);

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

        mSpyCurrentIkeSaRecord.close();
        mSpyLocalInitIkeSaRecord.close();
        mSpyRemoteInitIkeSaRecord.close();

        IkeMessage.setIkeMessageHelper(new IkeMessageHelper());
        SaRecord.setSaRecordHelper(new SaRecordHelper());
        ChildSessionStateMachineFactory.setChildSessionFactoryHelper(
                new ChildSessionFactoryHelper());
    }

    private IkeSessionStateMachine makeAndStartIkeSession(IkeSessionOptions ikeOptions)
            throws Exception {
        IkeSessionStateMachine ikeSession =
                new IkeSessionStateMachine(
                        mLooper.getLooper(),
                        mContext,
                        mIpSecManager,
                        ikeOptions,
                        mChildSessionOptions,
                        mSpyUserCbExecutor,
                        mMockIkeSessionCallback,
                        mMockChildSessionCallback,
                        mMockEapAuthenticatorFactory);
        ikeSession.setDbg(true);

        mLooper.dispatchAll();
        ikeSession.mLocalAddress = LOCAL_ADDRESS;

        mSpyIkeSocket = spy(IkeSocket.getIkeSocket(mUdpEncapSocket, ikeSession));
        doNothing().when(mSpyIkeSocket).sendIkePacket(any(), any());
        ikeSession.mIkeSocket = mSpyIkeSocket;

        return ikeSession;
    }

    static SaProposal buildSaProposal() throws Exception {
        return SaProposal.Builder.newIkeSaProposalBuilder()
                .addEncryptionAlgorithm(
                        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128)
                .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1)
                .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                .build();
    }

    private IkeSessionOptions.Builder buildIkeSessionOptionsCommon() throws Exception {
        return new IkeSessionOptions.Builder(REMOTE_ADDRESS, mUdpEncapSocket)
                .addSaProposal(buildSaProposal())
                .setLocalIdentification(new IkeIpv4AddrIdentification((Inet4Address) LOCAL_ADDRESS))
                .setRemoteIdentification(
                        new IkeIpv4AddrIdentification((Inet4Address) REMOTE_ADDRESS));
    }

    private IkeSessionOptions buildIkeSessionOptionsPsk(byte[] psk) throws Exception {
        return buildIkeSessionOptionsCommon().setAuthPsk(psk).build();
    }

    private IkeSessionOptions buildIkeSessionOptionsEap() throws Exception {
        return buildIkeSessionOptionsCommon()
                .setAuthEap(mock(X509Certificate.class), mEapSessionConfig)
                .build();
    }

    private ChildSessionOptions buildChildSessionOptions() throws Exception {
        SaProposal saProposal =
                SaProposal.Builder.newChildSaProposalBuilder()
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
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NOTIFY);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NOTIFY);

        payloadHexStringList.add(IKE_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(KE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NONCE_RESP_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NAT_DETECTION_SOURCE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NAT_DETECTION_DESTINATION_PAYLOAD_HEX_STRING);

        // In each test assign different IKE responder SPI in IKE INIT response to avoid remote SPI
        // collision during response validation.
        // STOPSHIP: b/131617794 allow #mockIkeSetup to be independent in each test after we can
        // support IkeSession cleanup.
        return makeDummyReceivedIkeInitRespPacket(
                1L /*initiator SPI*/,
                2L /*responder SPI*/,
                IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT,
                true /*isResp*/,
                false /*fromIkeInit*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeIkeAuthRespWithChildPayloads(List<IkePayload> authRelatedPayloads)
            throws Exception {
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_TS_INITIATOR);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_TS_RESPONDER);

        payloadHexStringList.add(CHILD_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(TS_INIT_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(TS_RESP_PAYLOAD_HEX_STRING);

        List<IkePayload> payloadList =
                hexStrListToIkePayloadList(payloadTypeList, payloadHexStringList, true /*isResp*/);
        payloadList.addAll(authRelatedPayloads);

        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_IKE_AUTH,
                true /*isResp*/,
                payloadList);
    }

    private ReceivedIkePacket makeIkeAuthRespWithoutChildPayloads(
            List<IkePayload> authRelatedPayloads) throws Exception {
        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_IKE_AUTH,
                true /*isResp*/,
                authRelatedPayloads);
    }

    private ReceivedIkePacket makeCreateChildCreateMessage(boolean isResp) throws Exception {
        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                isResp,
                makeCreateChildPayloadList(isResp));
    }

    private ReceivedIkePacket makeRekeyChildCreateMessage(boolean isResp, int spi)
            throws Exception {
        IkeNotifyPayload rekeyPayload =
                new IkeNotifyPayload(
                        IkePayload.PROTOCOL_ID_ESP,
                        spi,
                        IkeNotifyPayload.NOTIFY_TYPE_REKEY_SA,
                        new byte[0]);

        List<IkePayload> payloadList = makeCreateChildPayloadList(isResp);
        payloadList.add(rekeyPayload);

        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                isResp,
                payloadList);
    }

    private List<IkePayload> makeCreateChildPayloadList(boolean isResp) throws Exception {
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NONCE);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_TS_INITIATOR);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_TS_RESPONDER);

        payloadHexStringList.add(CHILD_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NONCE_RESP_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(TS_INIT_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(TS_RESP_PAYLOAD_HEX_STRING);

        return hexStrListToIkePayloadList(payloadTypeList, payloadHexStringList, isResp);
    }

    private ReceivedIkePacket makeDeleteChildPacket(IkeDeletePayload[] payloads, boolean isResp)
            throws Exception {
        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_INFORMATIONAL,
                isResp,
                Arrays.asList(payloads));
    }

    private ReceivedIkePacket makeRekeyIkeResponse() throws Exception {
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_KE);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NONCE);

        payloadHexStringList.add(IKE_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(KE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NONCE_RESP_PAYLOAD_HEX_STRING);

        return makeDummyEncryptedReceivedIkePacket(
                mSpyCurrentIkeSaRecord,
                IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                true /*isResp*/,
                payloadTypeList,
                payloadHexStringList);
    }

    private ReceivedIkePacket makeDeleteIkeResponse(IkeSaRecord ikeSaRecord) throws Exception {
        return makeDummyEncryptedReceivedIkePacket(
                ikeSaRecord,
                IkeHeader.EXCHANGE_TYPE_INFORMATIONAL,
                true /*isResp*/,
                new LinkedList<>(),
                new LinkedList<>());
    }

    private ReceivedIkePacket makeDpdIkeRequest(IkeSaRecord saRecord) throws Exception {
        return makeDummyEncryptedReceivedIkePacket(
                saRecord,
                IkeHeader.EXCHANGE_TYPE_INFORMATIONAL,
                false /*isResp*/,
                new LinkedList<>(),
                new LinkedList<>());
    }

    private ReceivedIkePacket makeDpdIkeRequest(int msgId, byte[] dummyIkePacketBytes)
            throws Exception {
        return makeDummyEncryptedReceivedIkePacketWithPayloadList(
                mSpyCurrentIkeSaRecord,
                EXCHANGE_TYPE_INFORMATIONAL,
                false /*isResp*/,
                msgId,
                new LinkedList<>(),
                dummyIkePacketBytes);
    }

    private ReceivedIkePacket makeRekeyIkeRequest() throws Exception {
        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_KE);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_NONCE);

        payloadHexStringList.add(IKE_REKEY_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(KE_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(NONCE_INIT_PAYLOAD_HEX_STRING);
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

    private static boolean isNotifyExist(
            List<IkePayload> payloadList, @IkeNotifyPayload.NotifyType int notifyType) {
        for (IkeNotifyPayload notify :
                IkePayload.getPayloadListForTypeInProvidedList(
                        PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class, payloadList)) {
            if (notify.notifyType == notifyType) return true;
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

    private void verifyRetransmissionStarted() {
        assertTrue(
                mIkeSessionStateMachine
                        .getHandler()
                        .hasMessages(IkeSessionStateMachine.CMD_RETRANSMIT));
    }

    private void verifyRetransmissionStopped() {
        assertFalse(
                mIkeSessionStateMachine
                        .getHandler()
                        .hasMessages(IkeSessionStateMachine.CMD_RETRANSMIT));
    }

    @Test
    public void testQuit() {
        mIkeSessionStateMachine.quit();
        mLooper.dispatchAll();

        verify(mSpyIkeSocket).releaseReference(eq(mIkeSessionStateMachine));
        verify(mSpyIkeSocket).close();
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

    private void setupMakeFirstIkeSa() throws Exception {
        // Inject IkeSaRecord and release IKE SPI resource since we will lose their references
        // later.
        when(mMockSaRecordHelper.makeFirstIkeSaRecord(any(), any(), any()))
                .thenAnswer(
                        (invocation) -> {
                            IkeSaRecordConfig config =
                                    (IkeSaRecordConfig) invocation.getArguments()[2];
                            config.initSpi.close();
                            config.respSpi.close();
                            return mSpyCurrentIkeSaRecord;
                        });
    }

    @Test
    public void testCreateIkeLocalIkeInit() throws Exception {
        setupMakeFirstIkeSa();

        // Send IKE INIT request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Receive IKE INIT response
        ReceivedIkePacket dummyReceivedIkePacket = makeIkeInitResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyReceivedIkePacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Validate outbound IKE INIT request
        verify(mMockIkeMessageHelper, times(2)).encode(mIkeMessageCaptor.capture());
        IkeMessage ikeInitReqMessage = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = ikeInitReqMessage.ikeHeader;
        assertEquals(IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT, ikeHeader.exchangeType);
        assertFalse(ikeHeader.isResponseMsg);
        assertTrue(ikeHeader.fromIkeInitiator);

        List<IkePayload> payloadList = ikeInitReqMessage.ikePayloadList;
        assertTrue(isIkePayloadExist(payloadList, IkePayload.PAYLOAD_TYPE_SA));
        assertTrue(isIkePayloadExist(payloadList, IkePayload.PAYLOAD_TYPE_KE));
        assertTrue(isIkePayloadExist(payloadList, IkePayload.PAYLOAD_TYPE_NONCE));
        assertTrue(isNotifyExist(payloadList, NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP));
        assertTrue(isNotifyExist(payloadList, NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP));

        verify(mSpyIkeSocket)
                .registerIke(eq(mSpyCurrentIkeSaRecord.getLocalSpi()), eq(mIkeSessionStateMachine));

        verify(mMockIkeMessageHelper)
                .decode(0, dummyReceivedIkePacket.ikeHeader, dummyReceivedIkePacket.ikePacketBytes);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.CreateIkeLocalIkeAuth);
        verifyRetransmissionStarted();

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
                        mIkeSaRecordConfigCaptor.capture());

        IkeSaRecordConfig ikeSaRecordConfig = mIkeSaRecordConfigCaptor.getValue();
        assertEquals(KEY_LEN_IKE_PRF, ikeSaRecordConfig.prf.getKeyLength());
        assertEquals(KEY_LEN_IKE_INTE, ikeSaRecordConfig.integrityKeyLength);
        assertEquals(KEY_LEN_IKE_ENCR, ikeSaRecordConfig.encryptionKeyLength);
        assertEquals(CMD_LOCAL_REQUEST_REKEY_IKE, ikeSaRecordConfig.futureRekeyEvent.procedureType);

        // Validate NAT detection
        assertTrue(mIkeSessionStateMachine.mIsLocalBehindNat);
        assertFalse(mIkeSessionStateMachine.mIsRemoteBehindNat);
    }

    private void setIkeInitResults() throws Exception {
        mIkeSessionStateMachine.mIkeCipher = mock(IkeCipher.class);
        mIkeSessionStateMachine.mIkeIntegrity = mock(IkeMacIntegrity.class);
        mIkeSessionStateMachine.mIkePrf = mock(IkeMacPrf.class);
        mIkeSessionStateMachine.mSaProposal = buildSaProposal();
        mIkeSessionStateMachine.mCurrentIkeSaRecord = mSpyCurrentIkeSaRecord;
        mIkeSessionStateMachine.mLocalAddress = LOCAL_ADDRESS;
        mIkeSessionStateMachine.mIsLocalBehindNat = true;
        mIkeSessionStateMachine.mIsRemoteBehindNat = false;
        mIkeSessionStateMachine.addIkeSaRecord(mSpyCurrentIkeSaRecord);
    }

    /** Initializes the mIkeSessionStateMachine in the IDLE state. */
    private void setupIdleStateMachine() throws Exception {
        setIkeInitResults();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mIdle);
        mLooper.dispatchAll();

        mDummyChildSmCallback =
                createChildAndGetChildSessionSmCallback(
                        mMockChildSessionStateMachine, CHILD_SPI_REMOTE, mMockChildSessionCallback);

        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    private void mockIkeInitAndTransitionToIkeAuth(State authState) throws Exception {
        setIkeInitResults();

        // Need to create a real IkeMacPrf instance for authentication because we cannot inject a
        // method stub for IkeMacPrf#signBytes. IkeMacPrf#signBytes is inheritted from a package
        // protected class IkePrf. We don't have the visibility to mock it.
        mIkeSessionStateMachine.mIkePrf =
                IkeMacPrf.create(
                        new PrfTransform(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1),
                        IkeMessage.getSecurityProvider());

        mIkeSessionStateMachine.mIkeInitRequestBytes = new byte[0];
        mIkeSessionStateMachine.mIkeInitResponseBytes = new byte[0];
        mIkeSessionStateMachine.mIkeInitNoncePayload = new IkeNoncePayload();
        mIkeSessionStateMachine.mIkeRespNoncePayload = new IkeNoncePayload();

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_FORCE_TRANSITION, authState);
        mLooper.dispatchAll();
    }

    private void setupChildStateMachineFactory(ChildSessionStateMachine child) {
        // After state machine start, add to the callback->statemachine map
        when(mMockChildSessionFactoryHelper.makeChildSessionStateMachine(
                        eq(mLooper.getLooper()),
                        eq(mContext),
                        eq(mChildSessionOptions),
                        eq(mSpyUserCbExecutor),
                        any(IChildSessionCallback.class),
                        any(IChildSessionSmCallback.class)))
                .thenReturn(child);
    }

    /**
     * Utility to register a new callback -> state machine mapping.
     *
     * <p>Must be used if IkeSessionStateMachine.openChildSession() is not called, but commands
     * injected instead.
     *
     * @param callback The callback to be used for the mapping
     * @param sm The ChildSessionStateMachine instance to be used.
     */
    private void registerChildStateMachine(
            IChildSessionCallback callback, ChildSessionStateMachine sm) {
        setupChildStateMachineFactory(sm);
        mIkeSessionStateMachine.registerChildSessionCallback(
                mChildSessionOptions, callback, false /*isFirstChild*/);
    }

    @Test
    public void testCreateAdditionalChild() throws Exception {
        setupIdleStateMachine();

        IChildSessionCallback childCallback = mock(IChildSessionCallback.class);
        ChildSessionStateMachine childStateMachine = mock(ChildSessionStateMachine.class);
        registerChildStateMachine(childCallback, childStateMachine);

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new ChildLocalRequest(
                        IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_CHILD,
                        childCallback,
                        mChildSessionOptions));
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
        verify(childStateMachine)
                .createChildSession(
                        eq(LOCAL_ADDRESS),
                        eq(REMOTE_ADDRESS),
                        any(), // udpEncapSocket
                        eq(mIkeSessionStateMachine.mIkePrf),
                        any()); // sk_d

        // Once for initial child, a second time for the additional child.
        verify(mMockChildSessionFactoryHelper)
                .makeChildSessionStateMachine(
                        eq(mLooper.getLooper()),
                        eq(mContext),
                        eq(mChildSessionOptions),
                        eq(mSpyUserCbExecutor),
                        eq(childCallback),
                        mChildSessionSmCbCaptor.capture());
        IChildSessionSmCallback cb = mChildSessionSmCbCaptor.getValue();

        // Mocking sending request
        cb.onOutboundPayloadsReady(
                IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                false /*isResp*/,
                new LinkedList<>(),
                childStateMachine);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());
        IkeMessage createChildRequest = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = createChildRequest.ikeHeader;
        assertEquals(IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA, ikeHeader.exchangeType);
        assertFalse(ikeHeader.isResponseMsg);
        assertTrue(ikeHeader.fromIkeInitiator);
        assertEquals(mSpyCurrentIkeSaRecord.getLocalRequestMessageId(), ikeHeader.messageId);
        assertTrue(createChildRequest.ikePayloadList.isEmpty());

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);

        // Mocking receiving response
        ReceivedIkePacket dummyCreateChildResp = makeCreateChildCreateMessage(true /*isResp*/);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyCreateChildResp);
        mLooper.dispatchAll();

        verifyIncrementLocaReqMsgId();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyCreateChildResp);

        verify(childStateMachine)
                .receiveResponse(
                        eq(IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA), mPayloadListCaptor.capture());

        List<IkePayload> childRespList = mPayloadListCaptor.getValue();
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_SA));
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_TS_INITIATOR));
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_TS_RESPONDER));
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_NONCE));

        // Mock finishing procedure
        cb.onProcedureFinished(childStateMachine);
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        verifyRetransmissionStopped();
    }

    @Test
    public void testTriggerDeleteChildLocal() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new ChildLocalRequest(
                        IkeSessionStateMachine.CMD_LOCAL_REQUEST_DELETE_CHILD,
                        mMockChildSessionCallback,
                        null /*childOptions*/));
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
        verify(mMockChildSessionStateMachine).deleteChildSession();
    }

    @Test
    public void testHandleDeleteChildBeforeCreation() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new ChildLocalRequest(
                        IkeSessionStateMachine.CMD_LOCAL_REQUEST_DELETE_CHILD,
                        mock(IChildSessionCallback.class),
                        null /*childOptions*/));
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testTriggerRekeyChildLocal() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new ChildLocalRequest(
                        IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_CHILD,
                        mMockChildSessionCallback,
                        null /*childOptions*/));
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
        verify(mMockChildSessionStateMachine).rekeyChildSession();
    }

    @Test
    public void testScheduleAndTriggerRekeyChildLocal() throws Exception {
        setupIdleStateMachine();
        long dummyRekeyTimeout = 10000L;

        ChildLocalRequest rekeyRequest =
                new ChildLocalRequest(
                        IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_CHILD,
                        mMockChildSessionCallback,
                        null /*childOptions*/);
        mDummyChildSmCallback.scheduleLocalRequest(rekeyRequest, dummyRekeyTimeout);

        mLooper.moveTimeForward(dummyRekeyTimeout);
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
        verify(mMockChildSessionStateMachine).rekeyChildSession();
    }

    private IChildSessionSmCallback createChildAndGetChildSessionSmCallback(
            ChildSessionStateMachine child, int remoteSpi) throws Exception {
        return createChildAndGetChildSessionSmCallback(
                child, remoteSpi, mock(IChildSessionCallback.class));
    }

    private IChildSessionSmCallback createChildAndGetChildSessionSmCallback(
            ChildSessionStateMachine child, int remoteSpi, IChildSessionCallback childCallback)
            throws Exception {
        registerChildStateMachine(childCallback, child);

        IChildSessionSmCallback cb = mIkeSessionStateMachine.new ChildSessionSmCallback();
        cb.onChildSaCreated(remoteSpi, child);
        mLooper.dispatchAll();

        return cb;
    }

    private void transitionToChildProcedureOngoing() {
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mChildProcedureOngoing);
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
    }

    private void verifyChildReceiveDeleteRequest(
            ChildSessionStateMachine child, IkeDeletePayload[] expectedDelPayloads) {
        verify(child)
                .receiveRequest(
                        eq(IKE_EXCHANGE_SUBTYPE_DELETE_CHILD),
                        eq(EXCHANGE_TYPE_INFORMATIONAL),
                        mPayloadListCaptor.capture());
        List<IkePayload> reqPayloads = mPayloadListCaptor.getValue();

        int numExpectedDelPayloads = expectedDelPayloads.length;
        assertEquals(numExpectedDelPayloads, reqPayloads.size());

        for (int i = 0; i < numExpectedDelPayloads; i++) {
            assertEquals(expectedDelPayloads[i], (IkeDeletePayload) reqPayloads.get(i));
        }
    }

    private void outboundDeleteChildPayloadsReady(
            IChildSessionSmCallback childSmCb,
            IkeDeletePayload delPayload,
            boolean isResp,
            ChildSessionStateMachine child) {
        List<IkePayload> outPayloadList = new LinkedList<>();
        outPayloadList.add(delPayload);
        childSmCb.onOutboundPayloadsReady(
                IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, isResp, outPayloadList, child);
        mLooper.dispatchAll();
    }

    private List<IkePayload> verifyOutInfoMsgHeaderAndGetPayloads(boolean isResp) {
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());
        IkeMessage deleteChildMessage = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = deleteChildMessage.ikeHeader;
        assertEquals(mSpyCurrentIkeSaRecord.getInitiatorSpi(), ikeHeader.ikeInitiatorSpi);
        assertEquals(mSpyCurrentIkeSaRecord.getResponderSpi(), ikeHeader.ikeResponderSpi);
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);
        assertEquals(isResp, ikeHeader.isResponseMsg);

        return deleteChildMessage.ikePayloadList;
    }

    @Test
    public void testDeferChildRequestToChildProcedureOngoing() throws Exception {
        setupIdleStateMachine();

        IkeDeletePayload[] inboundDelPayloads =
                new IkeDeletePayload[] {new IkeDeletePayload(new int[] {CHILD_SPI_REMOTE})};
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDeleteChildPacket(inboundDelPayloads, false /*isResp*/));
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
        verifyChildReceiveDeleteRequest(mMockChildSessionStateMachine, inboundDelPayloads);
    }

    @Test
    public void testRemoteDeleteOneChild() throws Exception {
        setupIdleStateMachine();
        transitionToChildProcedureOngoing();

        // Receive Delete Child Request
        IkeDeletePayload[] inboundDelPayloads =
                new IkeDeletePayload[] {new IkeDeletePayload(new int[] {CHILD_SPI_REMOTE})};
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDeleteChildPacket(inboundDelPayloads, false /*isResp*/));
        mLooper.dispatchAll();

        // Verify received payloads
        verifyChildReceiveDeleteRequest(mMockChildSessionStateMachine, inboundDelPayloads);

        // Outbound payload list ready
        IkeDeletePayload outDelPayload = new IkeDeletePayload(new int[] {CHILD_SPI_LOCAL});
        outboundDeleteChildPayloadsReady(
                mDummyChildSmCallback,
                outDelPayload,
                true /*isResp*/,
                mMockChildSessionStateMachine);

        // Verify outbound response
        List<IkePayload> payloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(1, payloadList.size());
        assertEquals(outDelPayload, ((IkeDeletePayload) payloadList.get(0)));
    }

    @Test
    public void testRemoteDeleteMultipleChildSession() throws Exception {
        ChildSessionStateMachine childOne = mock(ChildSessionStateMachine.class);
        int childOneRemoteSpi = 11;
        int childOneLocalSpi = 12;

        ChildSessionStateMachine childTwo = mock(ChildSessionStateMachine.class);
        int childTwoRemoteSpi = 21;
        int childTwoLocalSpi = 22;

        setupIdleStateMachine();
        IChildSessionSmCallback childSmCbOne =
                createChildAndGetChildSessionSmCallback(childOne, childOneRemoteSpi);
        IChildSessionSmCallback childSmCbTwo =
                createChildAndGetChildSessionSmCallback(childTwo, childTwoRemoteSpi);

        transitionToChildProcedureOngoing();

        // Receive Delete Child Request
        IkeDeletePayload[] inboundDelPayloads =
                new IkeDeletePayload[] {
                    new IkeDeletePayload(new int[] {childOneRemoteSpi, childTwoRemoteSpi})
                };
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDeleteChildPacket(inboundDelPayloads, false /*isResp*/));
        mLooper.dispatchAll();

        // Verify received payloads
        verifyChildReceiveDeleteRequest(childOne, inboundDelPayloads);
        verifyChildReceiveDeleteRequest(childTwo, inboundDelPayloads);

        // childOne outbound payload list ready
        IkeDeletePayload outDelPayloadOne = new IkeDeletePayload(new int[] {childOneLocalSpi});
        outboundDeleteChildPayloadsReady(childSmCbOne, outDelPayloadOne, true /*isResp*/, childOne);
        mLooper.dispatchAll();

        // Verify that no response is sent
        verify(mMockIkeMessageHelper, never())
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        any(IkeMessage.class));

        // childTwo outbound payload list ready
        IkeDeletePayload outDelPayloadTwo = new IkeDeletePayload(new int[] {childTwoLocalSpi});
        outboundDeleteChildPayloadsReady(childSmCbTwo, outDelPayloadTwo, true /*isResp*/, childTwo);
        mLooper.dispatchAll();

        // Verify outbound response
        List<IkePayload> payloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(2, payloadList.size());
        assertEquals(outDelPayloadOne, ((IkeDeletePayload) payloadList.get(0)));
        assertEquals(outDelPayloadTwo, ((IkeDeletePayload) payloadList.get(1)));
    }

    @Test
    public void testRemoteDeleteMultipleChildSaInSameSession() throws Exception {
        int newChildRemoteSpi = 21;
        int newChildLocalSpi = 22;

        setupIdleStateMachine();
        mDummyChildSmCallback.onChildSaCreated(newChildRemoteSpi, mMockChildSessionStateMachine);

        transitionToChildProcedureOngoing();

        // Receive Delete Child Request
        IkeDeletePayload[] inboundDelPayloads =
                new IkeDeletePayload[] {
                    new IkeDeletePayload(new int[] {CHILD_SPI_REMOTE}),
                    new IkeDeletePayload(new int[] {newChildRemoteSpi})
                };
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDeleteChildPacket(inboundDelPayloads, false /*isResp*/));
        mLooper.dispatchAll();

        // Verify received payloads
        verifyChildReceiveDeleteRequest(mMockChildSessionStateMachine, inboundDelPayloads);

        // child outbound payload list ready
        IkeDeletePayload outDelPayload =
                new IkeDeletePayload(new int[] {CHILD_SPI_LOCAL, newChildLocalSpi});
        outboundDeleteChildPayloadsReady(
                mDummyChildSmCallback,
                outDelPayload,
                true /*isResp*/,
                mMockChildSessionStateMachine);
        mLooper.dispatchAll();

        // Verify outbound response
        List<IkePayload> payloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(1, payloadList.size());
        assertEquals(outDelPayload, ((IkeDeletePayload) payloadList.get(0)));
    }

    @Test
    public void testIgnoreUnrecognizedChildSpi() throws Exception {
        int unrecognizedSpi = 2;

        setupIdleStateMachine();
        transitionToChildProcedureOngoing();

        // Receive Delete Child Request
        IkeDeletePayload[] inboundDelPayloads =
                new IkeDeletePayload[] {
                    new IkeDeletePayload(new int[] {unrecognizedSpi, CHILD_SPI_REMOTE})
                };
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDeleteChildPacket(inboundDelPayloads, false /*isResp*/));
        mLooper.dispatchAll();

        // Verify received payloads
        verifyChildReceiveDeleteRequest(mMockChildSessionStateMachine, inboundDelPayloads);

        // child outbound payload list ready
        IkeDeletePayload outPayload = new IkeDeletePayload(new int[] {CHILD_SPI_LOCAL});
        outboundDeleteChildPayloadsReady(
                mDummyChildSmCallback, outPayload, true /*isResp*/, mMockChildSessionStateMachine);
        mLooper.dispatchAll();

        // Verify outbound response
        List<IkePayload> payloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(1, payloadList.size());
        assertEquals(outPayload, ((IkeDeletePayload) payloadList.get(0)));
    }

    @Test
    public void testRemoteCreateChild() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                CMD_RECEIVE_IKE_PACKET, makeCreateChildCreateMessage(false /*isResp*/));

        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);

        List<IkePayload> ikePayloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(1, ikePayloadList.size());
        assertEquals(
                ERROR_TYPE_NO_ADDITIONAL_SAS,
                ((IkeNotifyPayload) ikePayloadList.get(0)).notifyType);
    }

    @Test
    public void testTriggerRemoteRekeyChild() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                CMD_RECEIVE_IKE_PACKET,
                makeRekeyChildCreateMessage(false /*isResp*/, CHILD_SPI_REMOTE));
        mLooper.dispatchAll();

        verify(mMockChildSessionStateMachine)
                .receiveRequest(
                        eq(IKE_EXCHANGE_SUBTYPE_REKEY_CHILD),
                        eq(EXCHANGE_TYPE_CREATE_CHILD_SA),
                        any(List.class));
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
    }

    @Test
    public void testHandleRekeyChildReqWithUnrecognizedSpi() throws Exception {
        int unrecognizedSpi = 2;

        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                CMD_RECEIVE_IKE_PACKET,
                makeRekeyChildCreateMessage(false /*isResp*/, unrecognizedSpi));
        mLooper.dispatchAll();

        verify(mMockChildSessionStateMachine, never()).receiveRequest(anyInt(), anyInt(), any());
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);

        List<IkePayload> ikePayloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(1, ikePayloadList.size());
        IkeNotifyPayload notifyPayload = (IkeNotifyPayload) ikePayloadList.get(0);
        assertEquals(ERROR_TYPE_CHILD_SA_NOT_FOUND, notifyPayload.notifyType);
        assertEquals(unrecognizedSpi, notifyPayload.spi);
    }

    private void verifyNotifyUserCloseSession() {
        verify(mSpyUserCbExecutor).execute(any(Runnable.class));
        verify(mMockIkeSessionCallback).onClosed();
    }

    @Test
    public void testRcvRemoteDeleteIkeWhenChildProcedureOngoing() throws Exception {
        setupIdleStateMachine();
        transitionToChildProcedureOngoing();

        mIkeSessionStateMachine.sendMessage(
                CMD_RECEIVE_IKE_PACKET, makeDeleteIkeRequest(mSpyCurrentIkeSaRecord));

        mLooper.dispatchAll();

        verifyNotifyUserCloseSession();

        // Verify state machine quit properly
        assertNull(mIkeSessionStateMachine.getCurrentState());

        List<IkePayload> ikePayloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertTrue(ikePayloadList.isEmpty());
    }

    @Test
    public void testRcvRemoteRekeyIkeWhenChildProcedureOngoing() throws Exception {
        setupIdleStateMachine();
        transitionToChildProcedureOngoing();

        mIkeSessionStateMachine.sendMessage(CMD_RECEIVE_IKE_PACKET, makeRekeyIkeRequest());

        mLooper.dispatchAll();

        // Since we have forced state machine to transition to ChildProcedureOngoing state without
        // really starting any Child procedure, it should transition to Idle at this time.
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);

        List<IkePayload> ikePayloadList = verifyOutInfoMsgHeaderAndGetPayloads(true /*isResp*/);
        assertEquals(1, ikePayloadList.size());
        assertEquals(
                ERROR_TYPE_TEMPORARY_FAILURE,
                ((IkeNotifyPayload) ikePayloadList.get(0)).notifyType);
    }

    @Test
    public void testKillChildSessions() throws Exception {
        setupIdleStateMachine();

        ChildSessionStateMachine childOne = mock(ChildSessionStateMachine.class);
        ChildSessionStateMachine childTwo = mock(ChildSessionStateMachine.class);
        registerChildStateMachine(mock(IChildSessionCallback.class), childOne);
        registerChildStateMachine(mock(IChildSessionCallback.class), childTwo);

        mIkeSessionStateMachine.mCurrentIkeSaRecord = null;

        mIkeSessionStateMachine.quitNow();

        mLooper.dispatchAll();

        verify(childOne).killSession();
        verify(childTwo).killSession();
    }

    private IkeMessage verifyAuthReqAndGetMsg() {
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

        return ikeAuthReqMessage;
    }

    private IkeMessage verifyAuthReqWithChildPayloadsAndGetMsg() {
        IkeMessage ikeAuthReqMessage = verifyAuthReqAndGetMsg();

        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_ID_INITIATOR, IkeIdPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_ID_RESPONDER, IkeIdPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_TS_INITIATOR, IkeTsPayload.class));
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_TS_RESPONDER, IkeTsPayload.class));

        return ikeAuthReqMessage;
    }

    private void verifySharedKeyAuthentication(
            IkeAuthPskPayload spyAuthPayload,
            IkeIdPayload respIdPayload,
            List<IkePayload> authRelatedPayloads,
            boolean hasChildPayloads)
            throws Exception {
        // Send IKE AUTH response to IKE state machine
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeIkeAuthRespWithChildPayloads(authRelatedPayloads));
        mLooper.dispatchAll();

        // Validate outbound IKE AUTH request
        IkeMessage ikeAuthReqMessage;
        if (hasChildPayloads) {
            ikeAuthReqMessage = verifyAuthReqWithChildPayloadsAndGetMsg();
        } else {
            ikeAuthReqMessage = verifyAuthReqAndGetMsg();
        }
        assertNotNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_AUTH, IkeAuthPskPayload.class));

        // Validate inbound IKE AUTH response
        verifyIncrementLocaReqMsgId();
        verify(mMockIkeMessageHelper).decode(anyInt(), any(), any(), any(), any(), any());

        // Validate authentication is done. Cannot use matchers because IkeAuthPskPayload is final.
        verify(spyAuthPayload)
                .verifyInboundSignature(
                        mPsk,
                        mIkeSessionStateMachine.mIkeInitRequestBytes,
                        mSpyCurrentIkeSaRecord.nonceInitiator,
                        respIdPayload.getEncodedPayloadBody(),
                        mIkeSessionStateMachine.mIkePrf,
                        mSpyCurrentIkeSaRecord.getSkPr());

        // Validate that user has been notified
        verify(mSpyUserCbExecutor).execute(any(Runnable.class));
        verify(mMockIkeSessionCallback).onOpened();

        // Verify payload list pair for first Child negotiation
        ArgumentCaptor<List<IkePayload>> mReqPayloadListCaptor =
                ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<IkePayload>> mRespPayloadListCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mMockChildSessionStateMachine)
                .handleFirstChildExchange(
                        mReqPayloadListCaptor.capture(),
                        mRespPayloadListCaptor.capture(),
                        eq(LOCAL_ADDRESS),
                        eq(REMOTE_ADDRESS),
                        any(), // udpEncapSocket
                        eq(mIkeSessionStateMachine.mIkePrf),
                        any()); // sk_d
        List<IkePayload> childReqList = mReqPayloadListCaptor.getValue();
        List<IkePayload> childRespList = mRespPayloadListCaptor.getValue();

        assertTrue(isIkePayloadExist(childReqList, IkePayload.PAYLOAD_TYPE_SA));
        assertTrue(isIkePayloadExist(childReqList, IkePayload.PAYLOAD_TYPE_TS_INITIATOR));
        assertTrue(isIkePayloadExist(childReqList, IkePayload.PAYLOAD_TYPE_TS_RESPONDER));
        assertTrue(isIkePayloadExist(childReqList, IkePayload.PAYLOAD_TYPE_NONCE));
        IkeSaPayload reqSaPayload =
                IkePayload.getPayloadForTypeInProvidedList(
                        IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class, childReqList);
        assertFalse(reqSaPayload.isSaResponse);

        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_SA));
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_TS_INITIATOR));
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_TS_RESPONDER));
        assertTrue(isIkePayloadExist(childRespList, IkePayload.PAYLOAD_TYPE_NONCE));
        IkeSaPayload respSaPayload =
                IkePayload.getPayloadForTypeInProvidedList(
                        IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class, childRespList);
        assertTrue(respSaPayload.isSaResponse);

        // Mock finishing first Child SA negotiation.
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);

        verify(mMockChildSessionFactoryHelper)
                .makeChildSessionStateMachine(
                        eq(mLooper.getLooper()),
                        eq(mContext),
                        eq(mChildSessionOptions),
                        eq(mSpyUserCbExecutor),
                        eq(mMockChildSessionCallback),
                        mChildSessionSmCbCaptor.capture());
        IChildSessionSmCallback cb = mChildSessionSmCbCaptor.getValue();

        cb.onProcedureFinished(mMockChildSessionStateMachine);
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testCreateIkeLocalIkeAuthPsk() throws Exception {
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuth);
        verifyRetransmissionStarted();

        // Build IKE AUTH response with Auth-PSK Payload and ID-Responder Payload.
        List<IkePayload> authRelatedPayloads = new LinkedList<>();
        IkeAuthPskPayload spyAuthPayload =
                spy(
                        (IkeAuthPskPayload)
                                IkeTestUtils.hexStringToIkePayload(
                                        IkePayload.PAYLOAD_TYPE_AUTH,
                                        true /*isResp*/,
                                        PSK_AUTH_RESP_PAYLOAD_HEX_STRING));

        doNothing()
                .when(spyAuthPayload)
                .verifyInboundSignature(any(), any(), any(), any(), any(), any());
        authRelatedPayloads.add(spyAuthPayload);

        IkeIdPayload respIdPayload =
                (IkeIdPayload)
                        IkeTestUtils.hexStringToIkePayload(
                                IkePayload.PAYLOAD_TYPE_ID_RESPONDER,
                                true /*isResp*/,
                                ID_PAYLOAD_RESPONDER_HEX_STRING);
        authRelatedPayloads.add(respIdPayload);

        verifySharedKeyAuthentication(spyAuthPayload, respIdPayload, authRelatedPayloads, true);
        verifyRetransmissionStopped();
    }

    @Test
    public void testCreateIkeLocalIkeAuthPreEap() throws Exception {
        mIkeSessionStateMachine.quitNow();
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Mock IKE INIT
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuth);
        verifyRetransmissionStarted();

        // Build IKE AUTH response with EAP Payload and ID-Responder Payload.

        // TODO: Also include Cert Payload.
        List<IkePayload> authRelatedPayloads = new LinkedList<>();

        authRelatedPayloads.add(new IkeEapPayload(EAP_DUMMY_MSG));

        IkeAuthDigitalSignPayload authPayload =
                (IkeAuthDigitalSignPayload)
                        IkeTestUtils.hexStringToIkePayload(
                                IkePayload.PAYLOAD_TYPE_AUTH,
                                true /*isResp*/,
                                GENERIC_DIGITAL_SIGN_AUTH_RESP_HEX_STRING);
        authRelatedPayloads.add(authPayload);

        IkeIdPayload respIdPayload =
                (IkeIdPayload)
                        IkeTestUtils.hexStringToIkePayload(
                                IkePayload.PAYLOAD_TYPE_ID_RESPONDER,
                                true /*isResp*/,
                                ID_PAYLOAD_RESPONDER_HEX_STRING);
        authRelatedPayloads.add(respIdPayload);

        // Send IKE AUTH response to IKE state machine
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeIkeAuthRespWithoutChildPayloads(authRelatedPayloads));
        mLooper.dispatchAll();

        // Validate outbound IKE AUTH request
        IkeMessage ikeAuthReqMessage = verifyAuthReqWithChildPayloadsAndGetMsg();
        assertNull(
                ikeAuthReqMessage.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_AUTH, IkeAuthPayload.class));

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.CreateIkeLocalIkeAuthInEap);
        verifyRetransmissionStopped();
        assertNotNull(mIkeSessionStateMachine.mInitIdPayload);
        assertNotNull(mIkeSessionStateMachine.mRespIdPayload);

        // TODO: Verify authentication is done
    }

    private IEapCallback verifyEapAuthenticatorCreatedAndGetCallback() {
        ArgumentCaptor<IEapCallback> captor = ArgumentCaptor.forClass(IEapCallback.class);

        verify(mMockEapAuthenticatorFactory)
                .newEapAuthenticator(
                        eq(mIkeSessionStateMachine.getHandler().getLooper()),
                        captor.capture(),
                        eq(mContext),
                        eq(mEapSessionConfig));

        return captor.getValue();
    }

    @Test
    public void testCreateIkeLocalIkeAuthInEapStartsAuthenticatorAndProxiesMessage()
            throws Exception {
        mIkeSessionStateMachine.quitNow();
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Setup state and go to IN_EAP state
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuthInEap);
        mLooper.dispatchAll();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EAP_START_EAP_AUTH, new IkeEapPayload(EAP_DUMMY_MSG));
        mLooper.dispatchAll();

        verifyEapAuthenticatorCreatedAndGetCallback();

        verify(mMockEapAuthenticator).processEapMessage(eq(EAP_DUMMY_MSG));
    }

    @Test
    public void testCreateIkeLocalIkeAuthInEapHandlesOutboundResponse() throws Exception {
        mIkeSessionStateMachine.quitNow();
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Setup state and go to IN_EAP state
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuthInEap);
        mLooper.dispatchAll();

        IEapCallback callback = verifyEapAuthenticatorCreatedAndGetCallback();
        callback.onResponse(EAP_DUMMY_MSG);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify EAP response
        IkeMessage resp = mIkeMessageCaptor.getValue();
        IkeHeader ikeHeader = resp.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_IKE_AUTH, ikeHeader.exchangeType);
        assertFalse(ikeHeader.isResponseMsg);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);

        assertEquals(1, resp.ikePayloadList.size());
        assertArrayEquals(EAP_DUMMY_MSG, ((IkeEapPayload) resp.ikePayloadList.get(0)).eapMessage);
    }

    @Test
    public void testCreateIkeLocalIkeAuthInEapHandlesSuccess() throws Exception {
        mIkeSessionStateMachine.quitNow();
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Setup state and go to IN_EAP state
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuthInEap);
        mLooper.dispatchAll();

        IEapCallback callback = verifyEapAuthenticatorCreatedAndGetCallback();

        // Setup dummy initIdPayload for next state.
        mIkeSessionStateMachine.mInitIdPayload = mock(IkeIdPayload.class);
        when(mIkeSessionStateMachine.mInitIdPayload.getEncodedPayloadBody())
                .thenReturn(new byte[0]);

        callback.onSuccess(mPsk, new byte[0]); // use mPsk as MSK, eMSK does not matter
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.CreateIkeLocalIkeAuthPostEap);
    }

    @Test
    public void testCreateIkeLocalIkeAuthInEapHandlesError() throws Exception {
        mIkeSessionStateMachine.quitNow();
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Setup state and go to IN_EAP state
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuthInEap);
        mLooper.dispatchAll();

        IEapCallback callback = verifyEapAuthenticatorCreatedAndGetCallback();

        Throwable error = new IllegalArgumentException();
        callback.onError(error);
        mLooper.dispatchAll();

        // Fires user error callbacks
        verify(mMockIkeSessionCallback).onError(argThat(err -> err.getCause() == error));

        // Verify state machine quit properly
        verify(mSpyCurrentIkeSaRecord).close();
        assertNull(mIkeSessionStateMachine.getCurrentState());
    }

    @Test
    public void testCreateIkeLocalIkeAuthInEapHandlesFailure() throws Exception {
        mIkeSessionStateMachine.quitNow();
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Setup state and go to IN_EAP state
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuthInEap);
        mLooper.dispatchAll();

        IEapCallback callback = verifyEapAuthenticatorCreatedAndGetCallback();
        callback.onFail();
        mLooper.dispatchAll();

        // Fires user error callbacks
        verify(mMockIkeSessionCallback).onError(any(AuthenticationFailedException.class));

        // Verify state machine quit properly
        verify(mSpyCurrentIkeSaRecord).close();
        assertNull(mIkeSessionStateMachine.getCurrentState());
    }

    @Test
    public void testCreateIkeLocalIkeAuthPostEap() throws Exception {
        mIkeSessionStateMachine.quitNow();
        reset(mMockChildSessionFactoryHelper);
        setupChildStateMachineFactory(mMockChildSessionStateMachine);
        mIkeSessionStateMachine = makeAndStartIkeSession(buildIkeSessionOptionsEap());

        // Setup dummy state from IkeAuthPreEap for next state.
        mIkeSessionStateMachine.mInitIdPayload = mock(IkeIdPayload.class);
        when(mIkeSessionStateMachine.mInitIdPayload.getEncodedPayloadBody())
                .thenReturn(new byte[0]);
        mIkeSessionStateMachine.mRespIdPayload =
                (IkeIdPayload)
                        IkeTestUtils.hexStringToIkePayload(
                                IkePayload.PAYLOAD_TYPE_ID_RESPONDER,
                                true /*isResp*/,
                                ID_PAYLOAD_RESPONDER_HEX_STRING);

        List<Integer> payloadTypeList = new LinkedList<>();
        List<String> payloadHexStringList = new LinkedList<>();

        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_SA);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_TS_INITIATOR);
        payloadTypeList.add(IkePayload.PAYLOAD_TYPE_TS_RESPONDER);

        payloadHexStringList.add(CHILD_SA_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(TS_INIT_PAYLOAD_HEX_STRING);
        payloadHexStringList.add(TS_RESP_PAYLOAD_HEX_STRING);

        mIkeSessionStateMachine.mFirstChildReqList =
                hexStrListToIkePayloadList(payloadTypeList, payloadHexStringList, false /*isResp*/);

        // Setup state and go to IN_EAP state
        mockIkeInitAndTransitionToIkeAuth(mIkeSessionStateMachine.mCreateIkeLocalIkeAuthPostEap);
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_EAP_FINISH_EAP_AUTH, mPsk);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Build IKE AUTH response with Auth-PSK Payload and ID-Responder Payload.
        List<IkePayload> authRelatedPayloads = new LinkedList<>();
        IkeAuthPskPayload spyAuthPayload =
                spy(
                        (IkeAuthPskPayload)
                                IkeTestUtils.hexStringToIkePayload(
                                        IkePayload.PAYLOAD_TYPE_AUTH,
                                        true /*isResp*/,
                                        PSK_AUTH_RESP_PAYLOAD_HEX_STRING));

        doNothing()
                .when(spyAuthPayload)
                .verifyInboundSignature(any(), any(), any(), any(), any(), any());
        authRelatedPayloads.add(spyAuthPayload);

        IkeIdPayload respIdPayload =
                (IkeIdPayload)
                        IkeTestUtils.hexStringToIkePayload(
                                IkePayload.PAYLOAD_TYPE_ID_RESPONDER,
                                true /*isResp*/,
                                ID_PAYLOAD_RESPONDER_HEX_STRING);

        verifySharedKeyAuthentication(spyAuthPayload, respIdPayload, authRelatedPayloads, false);
        verifyRetransmissionStopped();
    }

    @Test
    public void testRekeyIkeLocalCreateSendsRequest() throws Exception {
        setupIdleStateMachine();

        // Send Rekey-Create request
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalCreate);
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());
        verifyRetransmissionStarted();

        // Verify outbound message
        IkeMessage rekeyMsg = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = rekeyMsg.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA, ikeHeader.exchangeType);
        assertEquals(mSpyCurrentIkeSaRecord.getLocalRequestMessageId(), ikeHeader.messageId);
        assertFalse(ikeHeader.isResponseMsg);
        assertTrue(ikeHeader.fromIkeInitiator);

        // Verify SA payload & proposals
        IkeSaPayload saPayload =
                rekeyMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
        assertFalse(saPayload.isSaResponse);
        assertEquals(1, saPayload.proposalList.size());

        IkeSaPayload.IkeProposal proposal =
                (IkeSaPayload.IkeProposal) saPayload.proposalList.get(0);
        assertEquals(1, proposal.number); // Must be 1-indexed
        assertEquals(IkePayload.PROTOCOL_ID_IKE, proposal.protocolId);
        assertEquals(IkePayload.SPI_LEN_IKE, proposal.spiSize);
        assertEquals(mIkeSessionStateMachine.mSaProposal, proposal.saProposal);

        // Verify Nonce and KE payloads exist.
        assertNotNull(
                rekeyMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class));

        IkeKePayload kePayload =
                rekeyMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);
        assertNotNull(kePayload);
        assertTrue(kePayload.isOutbound);
    }

    @Test
    public void testRekeyIkeLocalCreateHandlesResponse() throws Exception {
        setupIdleStateMachine();

        // Send Rekey-Create request
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Prepare "rekeyed" SA
        when(mMockSaRecordHelper.makeRekeyedIkeSaRecord(
                        eq(mSpyCurrentIkeSaRecord), any(), any(), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Receive Rekey response
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket = makeRekeyIkeResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRespReceivedPacket);

        // Verify in delete state, and new SA record was saved:
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalDelete);
        verifyRetransmissionStarted();
        assertEquals(mSpyLocalInitIkeSaRecord, mIkeSessionStateMachine.mLocalInitNewIkeSaRecord);
        verify(mSpyIkeSocket)
                .registerIke(
                        eq(mSpyLocalInitIkeSaRecord.getLocalSpi()), eq(mIkeSessionStateMachine));
    }

    @Test
    public void testRekeyIkeLocalDeleteSendsRequest() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeLocalDelete
        mIkeSessionStateMachine.mLocalInitNewIkeSaRecord = mSpyLocalInitIkeSaRecord;
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeLocalDelete);
        mLooper.dispatchAll();

        // Verify Rekey-Delete request
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalDelete);
        verifyRetransmissionStarted();

        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify outbound message
        IkeMessage delMsg = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = delMsg.ikeHeader;
        assertEquals(mSpyCurrentIkeSaRecord.getInitiatorSpi(), ikeHeader.ikeInitiatorSpi);
        assertEquals(mSpyCurrentIkeSaRecord.getResponderSpi(), ikeHeader.ikeResponderSpi);
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);
        assertFalse(ikeHeader.isResponseMsg);

        List<IkeDeletePayload> deletePayloadList =
                delMsg.getPayloadListForType(
                        IkePayload.PAYLOAD_TYPE_DELETE, IkeDeletePayload.class);
        assertEquals(1, deletePayloadList.size());

        IkeDeletePayload deletePayload = deletePayloadList.get(0);
        assertEquals(IkePayload.PROTOCOL_ID_IKE, deletePayload.protocolId);
        assertEquals(0, deletePayload.numSpi);
        assertEquals(0, deletePayload.spiSize);
        assertArrayEquals(new int[0], deletePayload.spisToDelete);
    }

    private void verifyRekeyReplaceSa(IkeSaRecord newSaRecord) {
        verify(mSpyCurrentIkeSaRecord).close();
        verify(mSpyIkeSocket).unregisterIke(eq(mSpyCurrentIkeSaRecord.getLocalSpi()));
        verify(mSpyIkeSocket, never()).unregisterIke(eq(newSaRecord.getLocalSpi()));

        assertEquals(mIkeSessionStateMachine.mCurrentIkeSaRecord, newSaRecord);

        verify(mMockChildSessionStateMachine).setSkD(newSaRecord.getSkD());
    }

    @Test
    public void testRekeyIkeLocalDeleteHandlesResponse() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeLocalDelete
        mIkeSessionStateMachine.mLocalInitNewIkeSaRecord = mSpyLocalInitIkeSaRecord;
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeLocalDelete);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Receive Delete response
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRespReceivedPacket);

        // Verify final state - Idle, with new SA, and old SA closed.
        verifyRekeyReplaceSa(mSpyLocalInitIkeSaRecord);
        verify(mMockIkeSessionCallback, never()).onClosed();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        verifyRetransmissionStopped();
    }

    @Test
    public void testRekeyIkeLocalDeleteWithRequestOnNewSa() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeLocalDelete
        mIkeSessionStateMachine.mLocalInitNewIkeSaRecord = mSpyLocalInitIkeSaRecord;
        mIkeSessionStateMachine.addIkeSaRecord(mSpyLocalInitIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeLocalDelete);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Receive an empty (DPD) request on the new IKE SA
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDpdIkeRequest(mSpyLocalInitIkeSaRecord));
        mLooper.dispatchAll();

        // Verify final state - Idle, with new SA, and old SA closed.
        verifyRekeyReplaceSa(mSpyLocalInitIkeSaRecord);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
        verifyRetransmissionStopped();
    }

    @Test
    public void testRekeyIkeRemoteDeleteWithRequestOnNewSa() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeRemoteDelete
        mIkeSessionStateMachine.mRemoteInitNewIkeSaRecord = mSpyRemoteInitIkeSaRecord;
        mIkeSessionStateMachine.addIkeSaRecord(mSpyRemoteInitIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeRemoteDelete);
        mLooper.dispatchAll();

        // Receive an empty (DPD) request on the new IKE SA
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDpdIkeRequest(mSpyRemoteInitIkeSaRecord));
        mLooper.dispatchAll();

        // Verify final state - Idle, with new SA, and old SA closed.
        verifyRekeyReplaceSa(mSpyRemoteInitIkeSaRecord);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testRekeyIkeRemoteCreate() throws Exception {
        setupIdleStateMachine();

        when(mMockSaRecordHelper.makeRekeyedIkeSaRecord(
                        eq(mSpyCurrentIkeSaRecord), any(), any(), any(), any()))
                .thenReturn(mSpyRemoteInitIkeSaRecord);

        // Receive Rekey request
        ReceivedIkePacket dummyRekeyIkeRequestReceivedPacket = makeRekeyIkeRequest();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRequestReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementRemoteReqMsgId();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRequestReceivedPacket);

        // Verify SA created with correct parameters
        ArgumentCaptor<SaRecord.IkeSaRecordConfig> recordConfigCaptor =
                ArgumentCaptor.forClass(SaRecord.IkeSaRecordConfig.class);
        verify(mMockSaRecordHelper)
                .makeRekeyedIkeSaRecord(any(), any(), any(), any(), recordConfigCaptor.capture());
        assertEquals(IKE_REKEY_SA_INITIATOR_SPI, recordConfigCaptor.getValue().initSpi.getSpi());

        // Verify outbound CREATE_CHILD_SA message
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());
        IkeMessage rekeyCreateResp = mIkeMessageCaptor.getValue();
        IkeHeader rekeyCreateRespHeader = rekeyCreateResp.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, rekeyCreateRespHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA, rekeyCreateRespHeader.exchangeType);
        assertTrue(rekeyCreateRespHeader.isResponseMsg);
        assertTrue(rekeyCreateRespHeader.fromIkeInitiator);
        assertNotNull(
                rekeyCreateResp.getPayloadForType(IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class));
        assertNotNull(
                rekeyCreateResp.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class));
        assertNotNull(
                rekeyCreateResp.getPayloadForType(
                        IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class));

        // Verify SA, StateMachine state
        assertEquals(mSpyCurrentIkeSaRecord, mIkeSessionStateMachine.mIkeSaRecordAwaitingRemoteDel);
        assertEquals(mSpyRemoteInitIkeSaRecord, mIkeSessionStateMachine.mIkeSaRecordSurviving);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeRemoteDelete);
        verify(mSpyIkeSocket)
                .registerIke(
                        eq(mSpyRemoteInitIkeSaRecord.getLocalSpi()), eq(mIkeSessionStateMachine));
    }

    @Test
    public void testRekeyIkeRemoteDelete() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeLocalDelete
        mIkeSessionStateMachine.mRemoteInitNewIkeSaRecord = mSpyRemoteInitIkeSaRecord;
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeRemoteDelete);
        mLooper.dispatchAll();

        // Rekey Delete request
        ReceivedIkePacket dummyDeleteIkeRequestReceivedPacket =
                makeDeleteIkeRequest(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRequestReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementRemoteReqMsgId();
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRequestReceivedPacket);

        // Verify outbound DELETE_IKE_SA message
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());
        IkeMessage rekeyDeleteResp = mIkeMessageCaptor.getValue();
        IkeHeader rekeyDeleteRespHeader = rekeyDeleteResp.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, rekeyDeleteRespHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, rekeyDeleteRespHeader.exchangeType);
        assertTrue(rekeyDeleteRespHeader.isResponseMsg);
        assertTrue(rekeyDeleteRespHeader.fromIkeInitiator);
        assertTrue(rekeyDeleteResp.ikePayloadList.isEmpty());

        // Verify final state - Idle, with new SA, and old SA closed.
        verifyRekeyReplaceSa(mSpyRemoteInitIkeSaRecord);

        verify(mMockIkeSessionCallback, never()).onClosed();

        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRequestReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testRekeyIkeRemoteDeleteExitAndRenter() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeLocalDelete
        mIkeSessionStateMachine.mRemoteInitNewIkeSaRecord = mSpyRemoteInitIkeSaRecord;
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeRemoteDelete);
        mLooper.dispatchAll();

        // Trigger a timeout, and immediately re-enter remote-delete
        mLooper.moveTimeForward(IkeSessionStateMachine.REKEY_DELETE_TIMEOUT_MS / 2 + 1);
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.TIMEOUT_REKEY_REMOTE_DELETE_IKE);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeRemoteDelete);
        mLooper.dispatchAll();

        // Shift time forward, and assert the previous timeout was NOT fired.
        mLooper.moveTimeForward(IkeSessionStateMachine.REKEY_DELETE_TIMEOUT_MS / 2 + 1);
        mLooper.dispatchAll();

        // Verify no request received, or response sent.
        verify(mMockIkeMessageHelper, never()).decode(anyInt(), anyObject(), anyObject());
        verify(mMockIkeMessageHelper, never())
                .encryptAndEncode(
                        anyObject(), anyObject(), eq(mSpyCurrentIkeSaRecord), anyObject());

        // Verify final state has not changed - signal was not sent.
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeRemoteDelete);
    }

    @Test
    public void testRekeyIkeRemoteDeleteTimedOut() throws Exception {
        setupIdleStateMachine();

        // Seed fake rekey data and force transition to RekeyIkeLocalDelete
        mIkeSessionStateMachine.mRemoteInitNewIkeSaRecord = mSpyRemoteInitIkeSaRecord;
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeRemoteDelete);
        mLooper.dispatchAll();

        mLooper.moveTimeForward(IkeSessionStateMachine.REKEY_DELETE_TIMEOUT_MS);
        mLooper.dispatchAll();

        // Verify no request received, or response sent.
        verify(mMockIkeMessageHelper, never()).decode(anyInt(), anyObject(), anyObject());
        verify(mMockIkeMessageHelper, never())
                .encryptAndEncode(
                        anyObject(), anyObject(), eq(mSpyCurrentIkeSaRecord), anyObject());

        // Verify final state - Idle, with new SA, and old SA closed.
        verifyRekeyReplaceSa(mSpyRemoteInitIkeSaRecord);

        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testSimulRekey() throws Exception {
        setupIdleStateMachine();

        when(mMockSaRecordHelper.makeRekeyedIkeSaRecord(
                        eq(mSpyCurrentIkeSaRecord), any(), any(), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);
        when(mSpyLocalInitIkeSaRecord.compareTo(mSpyRemoteInitIkeSaRecord)).thenReturn(1);

        // Send Rekey request on mSpyCurrentIkeSaRecord
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));

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
        verify(mSpyIkeSocket)
                .registerIke(
                        eq(mSpyLocalInitIkeSaRecord.getLocalSpi()), eq(mIkeSessionStateMachine));

        // Receive Delete response on mSpyCurrentIkeSaRecord
        ReceivedIkePacket dummyDeleteIkeRespReceivedPacket =
                makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDeleteIkeRespReceivedPacket);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        // Verify
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRequestReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyRekeyIkeRespReceivedPacket);
        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDeleteIkeRespReceivedPacket);
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);

        verifyRekeyReplaceSa(mSpyLocalInitIkeSaRecord);
        verify(mMockIkeSessionCallback, never()).onClosed();
    }

    @Test
    public void testIkeInitSchedulesRekey() throws Exception {
        setupMakeFirstIkeSa();

        // Send IKE INIT request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        // Receive IKE INIT response
        ReceivedIkePacket dummyReceivedIkePacket = makeIkeInitResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyReceivedIkePacket);

        // Mock IKE AUTH and transition to Idle
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mIdle);
        mLooper.dispatchAll();
        mIkeSessionStateMachine.mSaProposal = buildSaProposal();

        // Move time forward to trigger rekey
        mLooper.moveTimeForward(SA_SOFT_LIFETIME_MS);
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalCreate);
    }

    @Test
    public void testRekeyCreateIkeSchedulesRekey() throws Exception {
        setupIdleStateMachine();

        // Send Rekey-Create request
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));
        mLooper.dispatchAll();

        // Prepare "rekeyed" SA
        when(mMockSaRecordHelper.makeRekeyedIkeSaRecord(
                        eq(mSpyCurrentIkeSaRecord), any(), any(), any(), any()))
                .thenReturn(mSpyLocalInitIkeSaRecord);

        // Receive Rekey response
        ReceivedIkePacket dummyRekeyIkeRespReceivedPacket = makeRekeyIkeResponse();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyRekeyIkeRespReceivedPacket);
        mLooper.dispatchAll();

        // Mock rekey delete and transition to Idle
        mIkeSessionStateMachine.mCurrentIkeSaRecord = mSpyLocalInitIkeSaRecord;
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mIdle);
        mLooper.dispatchAll();

        // Move time forward to trigger rekey
        mLooper.moveTimeForward(SA_SOFT_LIFETIME_MS);
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalCreate);
    }

    @Test
    public void testBuildEncryptedInformationalMessage() throws Exception {
        IkeNotifyPayload payload = new IkeNotifyPayload(ERROR_TYPE_INVALID_SYNTAX, new byte[0]);

        boolean isResp = false;
        IkeMessage generated =
                mIkeSessionStateMachine.buildEncryptedInformationalMessage(
                        mSpyCurrentIkeSaRecord, new IkeInformationalPayload[] {payload}, isResp, 0);

        assertEquals(mSpyCurrentIkeSaRecord.getInitiatorSpi(), generated.ikeHeader.ikeInitiatorSpi);
        assertEquals(mSpyCurrentIkeSaRecord.getResponderSpi(), generated.ikeHeader.ikeResponderSpi);
        assertEquals(
                mSpyCurrentIkeSaRecord.getLocalRequestMessageId(), generated.ikeHeader.messageId);
        assertEquals(isResp, generated.ikeHeader.isResponseMsg);
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, generated.ikeHeader.nextPayloadType);

        List<IkeNotifyPayload> generatedPayloads =
                generated.getPayloadListForType(
                        IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);
        assertEquals(1, generatedPayloads.size());

        IkeNotifyPayload generatedPayload = generatedPayloads.get(0);
        assertArrayEquals(new byte[0], generatedPayload.notifyData);
        assertEquals(ERROR_TYPE_INVALID_SYNTAX, generatedPayload.notifyType);
    }

    @Test
    public void testEncryptedRetransmitterImmediatelySendsRequest() throws Exception {
        setupIdleStateMachine();
        byte[] dummyLastRespBytes = "testRetransmitterSendsRequestLastResp".getBytes();
        mIkeSessionStateMachine.mLastSentIkeResp = dummyLastRespBytes;

        IkeMessage spyIkeReqMessage =
                spy(
                        new IkeMessage(
                                new IkeHeader(
                                        mSpyCurrentIkeSaRecord.getInitiatorSpi(),
                                        mSpyCurrentIkeSaRecord.getResponderSpi(),
                                        IkePayload.PAYLOAD_TYPE_SK,
                                        EXCHANGE_TYPE_INFORMATIONAL,
                                        false /*isResp*/,
                                        mSpyCurrentIkeSaRecord.isLocalInit,
                                        mSpyCurrentIkeSaRecord.getLocalRequestMessageId()),
                                new LinkedList<>()));

        // Use something unique as a sentinel value
        byte[] dummyReqBytes = "testRetransmitterSendsRequest".getBytes();
        doReturn(dummyReqBytes)
                .when(spyIkeReqMessage)
                .encryptAndEncode(any(), any(), eq(mSpyCurrentIkeSaRecord));

        IkeSessionStateMachine.EncryptedRetransmitter retransmitter =
                mIkeSessionStateMachine.new EncryptedRetransmitter(spyIkeReqMessage);

        // Verify message is sent out, and that request does not change cached retransmit-response
        // mLastSentIkeResp.
        verify(mSpyIkeSocket).sendIkePacket(eq(dummyReqBytes), eq(REMOTE_ADDRESS));
        assertArrayEquals(dummyLastRespBytes, mIkeSessionStateMachine.mLastSentIkeResp);
    }

    @Test
    public void testCacheLastRequestAndResponse() throws Exception {
        setupIdleStateMachine();
        mIkeSessionStateMachine.mLastReceivedIkeReq = null;
        mIkeSessionStateMachine.mLastSentIkeResp = null;

        byte[] dummyIkeReq = "testLastSentRequest".getBytes();
        byte[] dummyIkeResp = "testLastSentResponse".getBytes();

        when(mMockIkeMessageHelper.encryptAndEncode(
                        any(), any(), eq(mSpyCurrentIkeSaRecord), any(IkeMessage.class)))
                .thenReturn(dummyIkeResp);

        // Receive a DPD request, expect to send dummyIkeResp
        ReceivedIkePacket dummyDpdRequest =
                makeDpdIkeRequest(mSpyCurrentIkeSaRecord.getRemoteRequestMessageId(), dummyIkeReq);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDpdRequest);
        mLooper.dispatchAll();

        verify(mSpyIkeSocket).sendIkePacket(eq(dummyIkeResp), eq(REMOTE_ADDRESS));
        assertArrayEquals(dummyIkeResp, mIkeSessionStateMachine.mLastSentIkeResp);
        assertArrayEquals(dummyIkeReq, mIkeSessionStateMachine.mLastReceivedIkeReq);
    }

    @Test
    public void testReplyRetransmittedRequest() throws Exception {
        setupIdleStateMachine();

        // Mock last sent request and response
        byte[] dummyIkeReq = "testRcvRetransmittedRequestReq".getBytes();
        byte[] dummyIkeResp = "testRcvRetransmittedRequestResp".getBytes();
        mIkeSessionStateMachine.mLastReceivedIkeReq = dummyIkeReq;
        mIkeSessionStateMachine.mLastSentIkeResp = dummyIkeResp;
        mSpyCurrentIkeSaRecord.incrementRemoteRequestMessageId();

        // Build request with last validated message ID
        ReceivedIkePacket request =
                makeDpdIkeRequest(
                        mSpyCurrentIkeSaRecord.getRemoteRequestMessageId() - 1, dummyIkeReq);

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, request);

        mLooper.dispatchAll();

        assertArrayEquals(dummyIkeResp, mIkeSessionStateMachine.mLastSentIkeResp);
        verify(mSpyIkeSocket).sendIkePacket(eq(dummyIkeResp), eq(REMOTE_ADDRESS));

        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);
    }

    @Test
    public void testDiscardFakeRetransmittedRequest() throws Exception {
        setupIdleStateMachine();

        // Mock last sent request and response
        byte[] dummyIkeReq = "testDiscardFakeRetransmittedRequestReq".getBytes();
        byte[] dummyIkeResp = "testDiscardFakeRetransmittedRequestResp".getBytes();
        mIkeSessionStateMachine.mLastReceivedIkeReq = dummyIkeReq;
        mIkeSessionStateMachine.mLastSentIkeResp = dummyIkeResp;
        mSpyCurrentIkeSaRecord.incrementRemoteRequestMessageId();

        // Build request with last validated message ID but different bytes
        ReceivedIkePacket request =
                makeDpdIkeRequest(
                        mSpyCurrentIkeSaRecord.getRemoteRequestMessageId() - 1, new byte[0]);

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, request);

        mLooper.dispatchAll();

        assertArrayEquals(dummyIkeResp, mIkeSessionStateMachine.mLastSentIkeResp);
        verify(mSpyIkeSocket, never()).sendIkePacket(any(), any());
    }

    @Test
    public void testDeleteIkeLocalDeleteRequest() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_DELETE_IKE));
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify outbound message
        IkeMessage delMsg = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = delMsg.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertFalse(ikeHeader.isResponseMsg);
        assertTrue(ikeHeader.fromIkeInitiator);

        List<IkeDeletePayload> deletePayloadList =
                delMsg.getPayloadListForType(
                        IkePayload.PAYLOAD_TYPE_DELETE, IkeDeletePayload.class);
        assertEquals(1, deletePayloadList.size());

        IkeDeletePayload deletePayload = deletePayloadList.get(0);
        assertEquals(IkePayload.PROTOCOL_ID_IKE, deletePayload.protocolId);
        assertEquals(0, deletePayload.numSpi);
        assertEquals(0, deletePayload.spiSize);
        assertArrayEquals(new int[0], deletePayload.spisToDelete);
    }

    @Test
    public void testDeleteIkeLocalDeleteResponse() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_DELETE_IKE));
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        ReceivedIkePacket received = makeDeleteIkeResponse(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, received);
        mLooper.dispatchAll();
        verifyIncrementLocaReqMsgId();

        verifyNotifyUserCloseSession();

        // Verify state machine quit properly
        assertNull(mIkeSessionStateMachine.getCurrentState());
    }

    @Test
    public void testDeleteIkeLocalDeleteReceivedNonDeleteRequest() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_DELETE_IKE));
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Verify delete sent out.
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(), anyObject(), eq(mSpyCurrentIkeSaRecord), anyObject());
        reset(mMockIkeMessageHelper); // Discard value.
        when(mMockIkeMessageHelper.encryptAndEncode(any(), any(), any(), any()))
                .thenReturn(new byte[0]);

        ReceivedIkePacket received = makeRekeyIkeRequest();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, received);

        mLooper.dispatchAll();
        verifyRetransmissionStarted();
        verifyIncrementRemoteReqMsgId();

        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify outbound response
        IkeMessage resp = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = resp.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertTrue(ikeHeader.isResponseMsg);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);

        List<IkeNotifyPayload> notificationPayloadList =
                resp.getPayloadListForType(IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);
        assertEquals(1, notificationPayloadList.size());

        IkeNotifyPayload notifyPayload = notificationPayloadList.get(0);
        assertEquals(IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE, notifyPayload.notifyType);
    }

    @Test
    public void testDeleteIkeRemoteDelete() throws Exception {
        setupIdleStateMachine();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET,
                makeDeleteIkeRequest(mSpyCurrentIkeSaRecord));

        mLooper.dispatchAll();
        verifyIncrementRemoteReqMsgId();

        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify outbound message
        IkeMessage delMsg = mIkeMessageCaptor.getValue();

        IkeHeader ikeHeader = delMsg.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertTrue(ikeHeader.isResponseMsg);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);

        assertTrue(delMsg.ikePayloadList.isEmpty());

        verifyNotifyUserCloseSession();

        // Verify state machine quit properly
        assertNull(mIkeSessionStateMachine.getCurrentState());
    }

    @Test
    public void testReceiveDpd() throws Exception {
        setupIdleStateMachine();

        // Receive a DPD request, expect to stay in IDLE state
        ReceivedIkePacket dummyDpdRequest = makeDpdIkeRequest(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDpdRequest);
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState() instanceof IkeSessionStateMachine.Idle);

        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDpdRequest);
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify outbound response
        IkeMessage resp = mIkeMessageCaptor.getValue();
        IkeHeader ikeHeader = resp.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertTrue(ikeHeader.isResponseMsg);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);
        assertTrue(resp.ikePayloadList.isEmpty());
    }

    @Test
    public void testReceiveDpdNonIdle() throws Exception {
        setupIdleStateMachine();

        // Move to a non-idle state. Use RekeyIkeRemoteDelete, as it doesn't send out any requests.
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION,
                mIkeSessionStateMachine.mRekeyIkeRemoteDelete);
        mLooper.dispatchAll();

        // In a rekey state, receiving (and handling) a DPD should not result in a change of states
        ReceivedIkePacket dummyDpdRequest = makeDpdIkeRequest(mSpyCurrentIkeSaRecord);
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, dummyDpdRequest);
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeRemoteDelete);

        verifyDecodeEncryptedMessage(mSpyCurrentIkeSaRecord, dummyDpdRequest);
        verify(mMockIkeMessageHelper)
                .encryptAndEncode(
                        anyObject(),
                        anyObject(),
                        eq(mSpyCurrentIkeSaRecord),
                        mIkeMessageCaptor.capture());

        // Verify outbound response
        IkeMessage resp = mIkeMessageCaptor.getValue();
        IkeHeader ikeHeader = resp.ikeHeader;
        assertEquals(IkePayload.PAYLOAD_TYPE_SK, ikeHeader.nextPayloadType);
        assertEquals(IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, ikeHeader.exchangeType);
        assertTrue(ikeHeader.isResponseMsg);
        assertEquals(mSpyCurrentIkeSaRecord.isLocalInit, ikeHeader.fromIkeInitiator);
        assertTrue(resp.ikePayloadList.isEmpty());
    }

    @Test
    public void testIdleTriggersNewRequests() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));
        mLooper.dispatchAll();

        // Verify that the command is executed, and the state machine transitions to the right state
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalCreate);
        verifyRetransmissionStarted();
    }

    @Test
    public void testNonIdleStateDoesNotTriggerNewRequests() throws Exception {
        setupIdleStateMachine();

        // Force ourselves into a non-idle state
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mReceiving);
        mLooper.dispatchAll();
        verify(mMockIkeMessageHelper, never()).encryptAndEncode(any(), any(), any(), any());

        // Queue a local request, and expect that it is not run (yet)
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE,
                new LocalRequest(IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));
        mLooper.dispatchAll();

        // Verify that the state machine is still in the Receiving state
        verify(mMockIkeMessageHelper, never()).encryptAndEncode(any(), any(), any(), any());
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.Receiving);

        // Go back to Idle, and expect to immediately transition to RekeyIkeLocalCreate from the
        // queued request
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mIdle);
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.RekeyIkeLocalCreate);
        verify(mMockIkeMessageHelper, times(1)).encryptAndEncode(any(), any(), any(), any());
    }

    @Test
    public void testOpenChildSessionValidatesArgs() throws Exception {
        setupIdleStateMachine();

        // Expect failure - no callbacks provided
        try {
            mIkeSessionStateMachine.openChildSession(mChildSessionOptions, null);
        } catch (IllegalArgumentException expected) {
        }

        // Expect failure - callbacks already registered
        try {
            mIkeSessionStateMachine.openChildSession(
                    mChildSessionOptions, mMockChildSessionCallback);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testOpenChildSession() throws Exception {
        setupIdleStateMachine();

        IChildSessionCallback cb = mock(IChildSessionCallback.class);
        mIkeSessionStateMachine.openChildSession(mChildSessionOptions, cb);

        // Test that inserting the same cb returns an error, even before the state
        // machine has a chance to process it.
        try {
            mIkeSessionStateMachine.openChildSession(mChildSessionOptions, cb);
        } catch (IllegalArgumentException expected) {
        }

        verify(mMockChildSessionFactoryHelper)
                .makeChildSessionStateMachine(
                        eq(mLooper.getLooper()),
                        eq(mContext),
                        eq(mChildSessionOptions),
                        eq(mSpyUserCbExecutor),
                        eq(cb),
                        any());

        // Verify state in IkeSessionStateMachine
        mLooper.dispatchAll();
        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);

        synchronized (mIkeSessionStateMachine.mChildCbToSessions) {
            assertTrue(mIkeSessionStateMachine.mChildCbToSessions.containsKey(cb));
        }
    }

    @Test
    public void testCloseChildSessionValidatesArgs() throws Exception {
        setupIdleStateMachine();

        // Expect failure - callbacks not registered
        try {
            mIkeSessionStateMachine.closeChildSession(mock(IChildSessionCallback.class));
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testCloseChildSession() throws Exception {
        setupIdleStateMachine();

        mIkeSessionStateMachine.closeChildSession(mMockChildSessionCallback);
        mLooper.dispatchAll();

        assertTrue(
                mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.ChildProcedureOngoing);
    }

    @Test
    public void testCloseImmediatelyAfterOpenChildSession() throws Exception {
        setupIdleStateMachine();

        IChildSessionCallback cb = mock(IChildSessionCallback.class);
        mIkeSessionStateMachine.openChildSession(mChildSessionOptions, cb);

        // Verify that closing the session immediately still picks up the child callback
        // even before the looper has a chance to run.
        mIkeSessionStateMachine.closeChildSession(mMockChildSessionCallback);
    }

    @Test
    public void testOnChildSessionClosed() throws Exception {
        setupIdleStateMachine();

        mDummyChildSmCallback.onChildSessionClosed(mMockChildSessionCallback);

        synchronized (mIkeSessionStateMachine.mChildCbToSessions) {
            assertFalse(
                    mIkeSessionStateMachine.mChildCbToSessions.containsKey(
                            mMockChildSessionCallback));
        }
    }

    @Test
    public void testHandleExceptionInEnterState() throws Exception {
        IkeSessionOptions mockSessionOptions = mock(IkeSessionOptions.class);
        when(mockSessionOptions.getSaProposals()).thenThrow(mock(RuntimeException.class));

        IkeSessionStateMachine ikeSession =
                new IkeSessionStateMachine(
                        mLooper.getLooper(),
                        mContext,
                        mIpSecManager,
                        mockSessionOptions,
                        mChildSessionOptions,
                        mSpyUserCbExecutor,
                        mMockIkeSessionCallback,
                        mMockChildSessionCallback,
                        mMockEapAuthenticatorFactory);
        // Send IKE INIT request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        mLooper.dispatchAll();

        assertNull(ikeSession.getCurrentState());
        verify(mSpyUserCbExecutor).execute(any(Runnable.class));
        verify(mMockIkeSessionCallback).onError(any(IkeInternalException.class));
    }

    @Test
    public void testHandleExceptionInProcessStateMsg() throws Exception {
        setupIdleStateMachine();
        mIkeSessionStateMachine.sendMessage(
                IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, null /*receivedIkePacket*/);
        mLooper.dispatchAll();

        assertNull(mIkeSessionStateMachine.getCurrentState());
        verify(mSpyUserCbExecutor).execute(any(Runnable.class));
        verify(mMockIkeSessionCallback).onError(any(IkeInternalException.class));
    }

    @Test
    public void testCreateIkeLocalIkeInitRcvErrorNotify() throws Exception {
        // Send IKE INIT request
        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
        mLooper.dispatchAll();
        verifyRetransmissionStarted();

        // Receive IKE INIT response with erro notification.
        List<IkePayload> payloads = new LinkedList<>();
        payloads.add(new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_NO_PROPOSAL_CHOSEN));
        ReceivedIkePacket resp =
                makeDummyUnencryptedReceivedIkePacket(
                        1L /*initiator SPI*/,
                        2L /*respodner SPI*/,
                        IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT,
                        true /*isResp*/,
                        false /*fromIkeInit*/,
                        payloads);

        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET, resp);
        mLooper.dispatchAll();

        // Fires user error callbacks
        verify(mMockIkeSessionCallback)
                .onError(argThat(err -> err instanceof NoValidProposalChosenException));
        // Verify state machine quit properly
        assertNull(mIkeSessionStateMachine.getCurrentState());
    }
}
