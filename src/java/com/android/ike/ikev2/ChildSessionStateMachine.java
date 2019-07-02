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

import static com.android.ike.ikev2.IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.CMD_LOCAL_REQUEST_DELETE_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.IKE_EXCHANGE_SUBTYPE_DELETE_CHILD;
import static com.android.ike.ikev2.IkeSessionStateMachine.IKE_EXCHANGE_SUBTYPE_REKEY_CHILD;
import static com.android.ike.ikev2.SaProposal.DH_GROUP_NONE;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_SYNTAX;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_IKE_AUTH;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_INFORMATIONAL;
import static com.android.ike.ikev2.message.IkeHeader.ExchangeType;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_REKEY_SA;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_USE_TRANSPORT_MODE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_DELETE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_KE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NONCE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_SA;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_TS_INITIATOR;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_TS_RESPONDER;
import static com.android.ike.ikev2.message.IkePayload.PROTOCOL_ID_ESP;

import android.annotation.IntDef;
import android.annotation.Nullable;
import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.SecurityParameterIndex;
import android.net.IpSecManager.SpiUnavailableException;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.util.Pair;

import com.android.ike.ikev2.IkeSessionStateMachine.IkeExchangeSubType;
import com.android.ike.ikev2.SaRecord.ChildSaRecord;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.IkeInternalException;
import com.android.ike.ikev2.exceptions.IkeProtocolException;
import com.android.ike.ikev2.exceptions.InvalidKeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.exceptions.NoValidProposalChosenException;
import com.android.ike.ikev2.exceptions.TsUnacceptableException;
import com.android.ike.ikev2.message.IkeDeletePayload;
import com.android.ike.ikev2.message.IkeKePayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkeNotifyPayload;
import com.android.ike.ikev2.message.IkeNotifyPayload.NotifyType;
import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload;
import com.android.ike.ikev2.message.IkeSaPayload.ChildProposal;
import com.android.ike.ikev2.message.IkeSaPayload.DhGroupTransform;
import com.android.ike.ikev2.message.IkeTsPayload;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * ChildSessionStateMachine tracks states and manages exchanges of this Child Session.
 *
 * <p>ChildSessionStateMachine has two types of states. One type are states where there is no
 * ongoing procedure affecting Child Session (non-procedure state), including Initial, Closed, Idle
 * and Receiving. All other states are "procedure" states which are named as follows:
 *
 * <pre>
 * State Name = [Procedure Type] + [Exchange Initiator] + [Exchange Type].
 * - An IKE procedure consists of one or two IKE exchanges:
 *      Procedure Type = {CreateChild | DeleteChild | Info | RekeyChild | SimulRekeyChild}.
 * - Exchange Initiator indicates whether local or remote peer is the exchange initiator:
 *      Exchange Initiator = {Local | Remote}
 * - Exchange type defines the function of this exchange.
 *      Exchange Type = {Create | Delete}
 * </pre>
 */
public class ChildSessionStateMachine extends StateMachine {
    private static final String TAG = "ChildSessionStateMachine";

    /** Receive request for negotiating first Child SA. */
    private static final int CMD_HANDLE_FIRST_CHILD_EXCHANGE = 1;
    /** Receive a request from the remote. */
    private static final int CMD_HANDLE_RECEIVED_REQUEST = 2;
    /** Receive a reponse from the remote. */
    private static final int CMD_HANDLE_RECEIVED_RESPONSE = 3;
    /** Force state machine to a target state for testing purposes. */
    @VisibleForTesting static final int CMD_FORCE_TRANSITION = 99;

    private final Context mContext;
    private final IpSecManager mIpSecManager;

    /** User provided configurations. */
    private final ChildSessionOptions mChildSessionOptions;

    private final Handler mUserCbHandler;
    private final IChildSessionCallback mUserCallback;

    /** Callback to notify IKE Session the state changes. */
    private final IChildSessionSmCallback mChildSmCallback;

    // TODO: Also store ChildSessionCallback for notifying users.

    /** Local address assigned on device. */
    @VisibleForTesting InetAddress mLocalAddress;
    /** Remote address configured by users. */
    @VisibleForTesting InetAddress mRemoteAddress;

    /**
     * UDP-Encapsulated socket that allows IPsec traffic to pass through a NAT. Null if UDP
     * encapsulation is not needed.
     */
    @VisibleForTesting @Nullable UdpEncapsulationSocket mUdpEncapSocket;

    /** Crypto parameters. Updated upon initial negotiation or IKE SA rekey. */
    @VisibleForTesting IkeMacPrf mIkePrf;

    @VisibleForTesting byte[] mSkD;

    /** Package private SaProposal that represents the negotiated Child SA proposal. */
    @VisibleForTesting SaProposal mSaProposal;

    /** Negotiated local Traffic Selector. */
    @VisibleForTesting IkeTrafficSelector[] mLocalTs;
    /** Negotiated remote Traffic Selector. */
    @VisibleForTesting IkeTrafficSelector[] mRemoteTs;

    @VisibleForTesting IkeCipher mChildCipher;
    @VisibleForTesting IkeMacIntegrity mChildIntegrity;

    /** Package private */
    @VisibleForTesting ChildSaRecord mCurrentChildSaRecord;
    /** Package private */
    @VisibleForTesting ChildSaRecord mLocalInitNewChildSaRecord;

    @VisibleForTesting final State mInitial = new Initial();
    @VisibleForTesting final State mCreateChildLocalCreate = new CreateChildLocalCreate();
    @VisibleForTesting final State mClosed = new Closed();
    @VisibleForTesting final State mIdle = new Idle();
    @VisibleForTesting final State mDeleteChildLocalDelete = new DeleteChildLocalDelete();
    @VisibleForTesting final State mDeleteChildRemoteDelete = new DeleteChildRemoteDelete();
    @VisibleForTesting final State mRekeyChildLocalCreate = new RekeyChildLocalCreate();
    @VisibleForTesting final State mRekeyChildLocalDelete = new RekeyChildLocalDelete();

    /**
     * Builds a new uninitialized ChildSessionStateMachine
     *
     * <p>Upon creation, this state machine will await either the handleFirstChildExchange
     * (IKE_AUTH), or the createChildSession (Additional child creation beyond the first child) to
     * be called, both of which must pass keying and SA information.
     *
     * <p>This two-stage initialization is required to allow race-free user interaction with the IKE
     * Session keyed on the child state machine callbacks.
     *
     * <p>Package private
     */
    ChildSessionStateMachine(
            Looper looper,
            Context context,
            IpSecManager ipSecManager,
            ChildSessionOptions sessionOptions,
            Handler userCbHandler,
            IChildSessionCallback userCallback,
            IChildSessionSmCallback childSmCallback) {
        super(TAG, looper);

        mContext = context;
        mIpSecManager = ipSecManager;
        mChildSessionOptions = sessionOptions;

        mUserCbHandler = userCbHandler;
        mUserCallback = userCallback;
        mChildSmCallback = childSmCallback;

        addState(mInitial);
        addState(mCreateChildLocalCreate);
        addState(mClosed);
        addState(mIdle);
        addState(mDeleteChildLocalDelete);
        addState(mDeleteChildRemoteDelete);
        addState(mRekeyChildLocalCreate);
        addState(mRekeyChildLocalDelete);

        setInitialState(mInitial);
    }

    /**
     * Interface for ChildSessionStateMachine to notify IkeSessionStateMachine of state changes.
     *
     * <p>Child Session may encounter an IKE Session fatal error in three cases with different
     * handling rules:
     *
     * <pre>
     * - When there is a fatal error in an inbound request, onOutboundPayloadsReady will be
     *   called first to send out an error notification and then onFatalIkeSessionError(false)
     *   will be called to locally close the IKE Session.
     * - When there is a fatal error in an inbound response, only onFatalIkeSessionError(true)
     *   will be called to notify the remote with a Delete request and then close the IKE Session.
     * - When there is an fatal error notification in an inbound response, only
     *   onFatalIkeSessionError(false) is called to close the IKE Session locally.
     * </pre>
     *
     * <p>Package private.
     */
    interface IChildSessionSmCallback {
        /** Notify that new Child SA is created. */
        void onChildSaCreated(int remoteSpi, ChildSessionStateMachine childSession);

        /** Notify that a Child SA is deleted. */
        void onChildSaDeleted(int remoteSpi);

        /** Notify the IKE Session to send out IKE message for this Child Session. */
        void onOutboundPayloadsReady(
                @ExchangeType int exchangeType,
                boolean isResp,
                List<IkePayload> payloadList,
                ChildSessionStateMachine childSession);

        /** Notify that a Child procedure has been finished. */
        void onProcedureFinished(ChildSessionStateMachine childSession);

        /**
         * Notify the IKE Session State Machine that this Child has been fully shut down.
         *
         * <p>This method MUST be called after the user callbacks have been fired, and MUST always
         * be called before the state machine can shut down.
         */
        void onChildSessionClosed(IChildSessionCallback userCallbacks);

        /**
         * Notify that a Child procedure has been finished and the IKE Session should close itself
         * because of a fatal error.
         *
         * <p>The IKE Session should send a Delete IKE request before closing when needsNotifyRemote
         * is true.
         */
        void onFatalIkeSessionError(boolean needsNotifyRemote);
    }

    /**
     * Receive requesting and responding payloads for negotiating first Child SA.
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     *
     * @param reqPayloads SA negotiation related payloads in IKE_AUTH request.
     * @param respPayloads SA negotiation related payloads in IKE_AUTH response.
     * @param localAddress The local (outer) address of the Child Session.
     * @param remoteAddress The remote (outer) address of the Child Session.
     * @param udpEncapSocket The socket to use for UDP encapsulation, or NULL if no encap needed.
     * @param ikePrf The pseudo-random function to use for key derivation
     * @param skD The key for which to derive new keying information from.
     */
    public void handleFirstChildExchange(
            List<IkePayload> reqPayloads,
            List<IkePayload> respPayloads,
            InetAddress localAddress,
            InetAddress remoteAddress,
            UdpEncapsulationSocket udpEncapSocket,
            IkeMacPrf ikePrf,
            byte[] skD) {
        registerProvisionalChildSession(respPayloads);
        this.mLocalAddress = localAddress;
        this.mRemoteAddress = remoteAddress;
        this.mUdpEncapSocket = udpEncapSocket;
        this.mIkePrf = ikePrf;
        this.mSkD = skD;

        sendMessage(
                CMD_HANDLE_FIRST_CHILD_EXCHANGE,
                new FirstChildNegotiationData(reqPayloads, respPayloads));
    }

    /**
     * Initiate Create Child procedure.
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     *
     * @param localAddress The local (outer) address from which traffic will originate.
     * @param remoteAddress The remote (outer) address to which traffic will be sent.
     * @param udpEncapSocket The socket to use for UDP encapsulation, or NULL if no encap needed.
     * @param ikePrf The pseudo-random function to use for key derivation
     * @param skD The key for which to derive new keying information from.
     */
    public void createChildSession(
            InetAddress localAddress,
            InetAddress remoteAddress,
            UdpEncapsulationSocket udpEncapSocket,
            IkeMacPrf ikePrf,
            byte[] skD) {
        this.mLocalAddress = localAddress;
        this.mRemoteAddress = remoteAddress;
        this.mUdpEncapSocket = udpEncapSocket;
        this.mIkePrf = ikePrf;
        this.mSkD = skD;

        sendMessage(CMD_LOCAL_REQUEST_CREATE_CHILD);
    }

    /**
     * Initiate Delete Child procedure.
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     */
    public void deleteChildSession() {
        sendMessage(CMD_LOCAL_REQUEST_DELETE_CHILD);
    }

    /**
     * Initiate Rekey Child procedure.
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     */
    public void rekeyChildSession() {
        sendMessage(CMD_LOCAL_REQUEST_REKEY_CHILD);
    }

    /**
     * Receive a request
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     *
     * @param exchangeSubtype the exchange subtype of this inbound request.
     * @param payloadList the Child-procedure-related payload list in the request message that needs
     *     validation.
     */
    public void receiveRequest(
            @IkeExchangeSubType int exchangeSubtype, List<IkePayload> payloadList) {
        sendMessage(CMD_HANDLE_RECEIVED_REQUEST, new ReceivedRequest(exchangeSubtype, payloadList));
    }

    /**
     * Receive a response.
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     *
     * @param exchangeType the exchange type in the response message that needs validation.
     * @param payloadList the Child-procedure-related payload list in the response message that
     *     needs validation.
     */
    public void receiveResponse(@ExchangeType int exchangeType, List<IkePayload> payloadList) {
        // If we are waiting for a Create/RekeyCreate response and the received message contains SA
        // payload we need to register for this provisional Child.

        if (isAwaitingCreateResp()
                && IkePayload.getPayloadForTypeInProvidedList(
                                PAYLOAD_TYPE_SA, IkeSaPayload.class, payloadList)
                        != null) {
            registerProvisionalChildSession(payloadList);
        }
        sendMessage(CMD_HANDLE_RECEIVED_RESPONSE, new ReceivedResponse(exchangeType, payloadList));
    }

    private boolean isAwaitingCreateResp() {
        return (getCurrentState() == mCreateChildLocalCreate
                || getCurrentState() == mRekeyChildLocalCreate);
    }

    /**
     * Update SK_d with provided value when IKE SA is rekeyed.
     *
     * @param skD the new skD in byte array.
     */
    public void setSkD(byte[] skD) {
        mSkD = skD;
    }

    /**
     * Register provisioning ChildSessionStateMachine in IChildSessionSmCallback
     *
     * <p>This method is for avoiding CHILD_SA_NOT_FOUND error in IkeSessionStateMachine when remote
     * peer sends request for delete/rekey this Child SA before ChildSessionStateMachine sends
     * FirstChildNegotiationData to itself.
     */
    private void registerProvisionalChildSession(List<IkePayload> respPayloads) {
        // When decoding responding IkeSaPayload in IkeSessionStateMachine, it is validated that
        // IkeSaPayload has exactly one IkeSaPayload.Proposal.
        IkeSaPayload saPayload = null;
        for (IkePayload payload : respPayloads) {
            if (payload.payloadType == IkePayload.PAYLOAD_TYPE_SA) {
                saPayload = (IkeSaPayload) payload;
                break;
            }
        }
        if (saPayload == null) {
            throw new IllegalArgumentException(
                    "Receive no SA payload for first Child SA negotiation.");
        }
        // IkeSaPayload.Proposal stores SPI in long type so as to be applied to both 8-byte IKE SPI
        // and 4-byte Child SPI. Here we cast the stored SPI to int to represent a Child SPI.
        int remoteGenSpi = (int) (saPayload.proposalList.get(0).spi);
        mChildSmCallback.onChildSaCreated(remoteGenSpi, this);
    }

    private void replyErrorNotification(@NotifyType int notifyType) {
        replyErrorNotification(notifyType, new byte[0]);
    }

    private void replyErrorNotification(@NotifyType int notifyType, byte[] notifyData) {
        List<IkePayload> outPayloads = new ArrayList<>(1);
        IkeNotifyPayload notifyPayload = new IkeNotifyPayload(notifyType, notifyData);
        outPayloads.add(notifyPayload);

        mChildSmCallback.onOutboundPayloadsReady(
                EXCHANGE_TYPE_INFORMATIONAL, true /*isResp*/, outPayloads, this);
    }

    /**
     * FirstChildNegotiationData contains payloads for negotiating first Child SA in IKE_AUTH
     * request and IKE_AUTH response and callback to notify IkeSessionStateMachine the SA
     * negotiation result.
     */
    private static class FirstChildNegotiationData {
        public final List<IkePayload> requestPayloads;
        public final List<IkePayload> responsePayloads;

        FirstChildNegotiationData(List<IkePayload> reqPayloads, List<IkePayload> respPayloads) {
            requestPayloads = reqPayloads;
            responsePayloads = respPayloads;
        }
    }

    /**
     * ReceivedRequest contains exchange subtype and payloads that are extracted from a request
     * message to the current Child procedure.
     */
    private static class ReceivedRequest {
        @IkeExchangeSubType public final int exchangeSubtype;
        public final List<IkePayload> requestPayloads;

        ReceivedRequest(@IkeExchangeSubType int eType, List<IkePayload> reqPayloads) {
            exchangeSubtype = eType;
            requestPayloads = reqPayloads;
        }
    }

    /**
     * ReceivedResponse contains exchange type and payloads that are extracted from a response
     * message to the current Child procedure.
     */
    private static class ReceivedResponse {
        public final int exchangeType;
        public final List<IkePayload> responsePayloads;

        ReceivedResponse(@ExchangeType int eType, List<IkePayload> respPayloads) {
            exchangeType = eType;
            responsePayloads = respPayloads;
        }
    }

    /**
     * InitCreateChildBase represents the common information for negotiating the initial Child SA
     * for setting up this Child Session.
     */
    private abstract class InitCreateChildBase extends State {
        protected void validateAndBuildChild(
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                @ExchangeType int exchangeType,
                @ExchangeType int expectedExchangeType) {
            CreateChildResult createChildResult =
                    CreateChildSaHelper.validateAndNegotiateInitChild(
                            reqPayloads,
                            respPayloads,
                            exchangeType,
                            expectedExchangeType,
                            mChildSessionOptions.isTransportMode(),
                            mIpSecManager,
                            mRemoteAddress);
            switch (createChildResult.status) {
                case CREATE_STATUS_OK:
                    try {
                        setUpNegotiatedResult(createChildResult);
                        mCurrentChildSaRecord =
                                ChildSaRecord.makeChildSaRecord(
                                        mContext,
                                        reqPayloads,
                                        respPayloads,
                                        createChildResult.localSpi,
                                        createChildResult.remoteSpi,
                                        mLocalAddress,
                                        mRemoteAddress,
                                        mUdpEncapSocket,
                                        mIkePrf,
                                        mChildIntegrity,
                                        mChildCipher,
                                        mSkD,
                                        mChildSessionOptions.isTransportMode(),
                                        true /*isLocalInit*/);
                        // TODO: Add mCurrentChildSaRecord in mSpiToSaRecordMap.
                        transitionTo(mIdle);
                    } catch (GeneralSecurityException
                            | ResourceUnavailableException
                            | SpiUnavailableException
                            | IOException e) {
                        // #makeChildSaRecord failed.
                        createChildResult.localSpi.close();
                        createChildResult.remoteSpi.close();
                        // TODO: Initiate deletion and close this Child Session
                        throw new UnsupportedOperationException("Cannot handle this error");
                    }
                    break;
                case CREATE_STATUS_CHILD_ERROR_INVALID_MSG:
                    // TODO: Initiate deletion and close this Child Session
                    throw new UnsupportedOperationException("Cannot handle this error");
                case CREATE_STATUS_CHILD_ERROR_RCV_NOTIFY:
                    // TODO: Unregister remotely generated SPI and locally close the Child Session.
                    throw new UnsupportedOperationException("Cannot handle this error");
                case CREATE_STATUS_IKE_ERROR:
                    // TODO: Unregister remotely generated SPI and locally close the Child Session.
                    mChildSmCallback.onFatalIkeSessionError(true /*needsNotifyRemote*/);
                    break;
                default:
                    throw new IllegalArgumentException("Unrecognized status");
            }
        }

        private void setUpNegotiatedResult(CreateChildResult createChildResult) {
            // Build crypto tools using negotiated SaProposal. It is ensured by {@link
            // IkeSaPayload#getVerifiedNegotiatedChildProposalPair} that the negotiated SaProposal
            // is valid. The negotiated SaProposal has exactly one encryption algorithm. When it has
            // a combined-mode encryption algorithm, it either does not have integrity
            // algorithm or only has one NONE value integrity algorithm. When the negotiated
            // SaProposal has a normal encryption algorithm, it either does not have integrity
            // algorithm or has one integrity algorithm with any supported value.

            mSaProposal = createChildResult.negotiatedProposal;
            Provider provider = IkeMessage.getSecurityProvider();
            mChildCipher = IkeCipher.create(mSaProposal.getEncryptionTransforms()[0], provider);
            if (mSaProposal.getIntegrityTransforms().length != 0
                    && mSaProposal.getIntegrityTransforms()[0].id
                            != SaProposal.INTEGRITY_ALGORITHM_NONE) {
                mChildIntegrity =
                        IkeMacIntegrity.create(mSaProposal.getIntegrityTransforms()[0], provider);
            }

            mLocalTs = createChildResult.localTs;
            mRemoteTs = createChildResult.remoteTs;
        }
    }

    /** Initial state of ChildSessionStateMachine. */
    class Initial extends InitCreateChildBase {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_HANDLE_FIRST_CHILD_EXCHANGE:
                    FirstChildNegotiationData childNegotiationData =
                            (FirstChildNegotiationData) message.obj;
                    List<IkePayload> reqPayloads = childNegotiationData.requestPayloads;
                    List<IkePayload> respPayloads = childNegotiationData.responsePayloads;

                    // Negotiate Child SA. The exchangeType has been validated in
                    // IkeSessionStateMachine. Won't validate it again here.
                    validateAndBuildChild(
                            reqPayloads,
                            respPayloads,
                            EXCHANGE_TYPE_IKE_AUTH,
                            EXCHANGE_TYPE_IKE_AUTH);

                    return HANDLED;
                case CMD_LOCAL_REQUEST_CREATE_CHILD:
                    transitionTo(mCreateChildLocalCreate);
                    return HANDLED;
                case CMD_FORCE_TRANSITION:
                    transitionTo((State) message.obj);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * CreateChildLocalCreate represents the state where Child Session initiates the Create Child
     * exchange.
     */
    class CreateChildLocalCreate extends InitCreateChildBase {
        private List<IkePayload> mRequestPayloads;

        @Override
        public void enter() {
            try {
                mRequestPayloads =
                        CreateChildSaHelper.getInitChildCreateReqPayloads(
                                mIpSecManager,
                                mLocalAddress,
                                mChildSessionOptions,
                                false /*isFirstChild*/);
                mChildSmCallback.onOutboundPayloadsReady(
                        EXCHANGE_TYPE_CREATE_CHILD_SA,
                        false /*isResp*/,
                        mRequestPayloads,
                        ChildSessionStateMachine.this);
            } catch (ResourceUnavailableException e) {
                // TODO: Notify users and close the Child Session.
            }
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_HANDLE_RECEIVED_RESPONSE:
                    ReceivedResponse rcvResp = (ReceivedResponse) message.obj;
                    validateAndBuildChild(
                            mRequestPayloads,
                            rcvResp.responsePayloads,
                            rcvResp.exchangeType,
                            EXCHANGE_TYPE_CREATE_CHILD_SA);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Closed represents the state when this ChildSessionStateMachine is closed, and no further
     * actions can be performed on it.
     */
    class Closed extends State {
        // TODO: Implement it.
    }

    /**
     * Idle represents a state when there is no ongoing IKE exchange affecting established Child SA.
     */
    class Idle extends State {
        @Override
        public void enter() {
            mChildSmCallback.onProcedureFinished(ChildSessionStateMachine.this);
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_LOCAL_REQUEST_DELETE_CHILD:
                    transitionTo(mDeleteChildLocalDelete);
                    return HANDLED;
                case CMD_LOCAL_REQUEST_REKEY_CHILD:
                    transitionTo(mRekeyChildLocalCreate);
                    return HANDLED;
                case CMD_HANDLE_RECEIVED_REQUEST:
                    ReceivedRequest req = (ReceivedRequest) message.obj;
                    switch (req.exchangeSubtype) {
                        case IKE_EXCHANGE_SUBTYPE_DELETE_CHILD:
                            deferMessage(message);
                            transitionTo(mDeleteChildRemoteDelete);
                            return HANDLED;
                        default:
                            // TODO: Handle remote rekey request
                            return NOT_HANDLED;
                    }
                default:
                    return NOT_HANDLED;
            }
        }

        // TODO: Support local rekey request,  remote rekey request and remote delete request.
    }

    /**
     * DeleteResponderBase represents all states after Child Session is established
     *
     * <p>All post-init states share common functionality of being able to respond to Delete Child
     * requests.
     */
    private abstract class DeleteResponderBase extends State {
        /**
         * Check if the payload list has a Delete Payload that includes the remote SPI of the input
         * ChildSaRecord.
         */
        protected boolean hasRemoteChildSpi(
                List<IkePayload> payloads, ChildSaRecord expectedRecord) {
            List<IkeDeletePayload> delPayloads =
                    IkePayload.getPayloadListForTypeInProvidedList(
                            PAYLOAD_TYPE_DELETE, IkeDeletePayload.class, payloads);

            for (IkeDeletePayload delPayload : delPayloads) {
                for (int spi : delPayload.spisToDelete) {
                    if (spi == expectedRecord.getRemoteSpi()) return true;
                }
            }
            return false;
        }

        /**
         * Build and send payload list that has a Delete Payload that includes the local SPI of the
         * input ChildSaRecord.
         */
        protected void sendDeleteChild(ChildSaRecord childSaRecord, boolean isResp) {
            List<IkePayload> outIkePayloads = new ArrayList<>(1);
            outIkePayloads.add(new IkeDeletePayload(new int[] {childSaRecord.getLocalSpi()}));

            mChildSmCallback.onOutboundPayloadsReady(
                    EXCHANGE_TYPE_INFORMATIONAL,
                    isResp,
                    outIkePayloads,
                    ChildSessionStateMachine.this);
        }

        /**
         * Helper method for responding to a session deletion request
         *
         * <p>Note that this method expects that the session is keyed on the mCurrentChildSaRecord
         * and closing this Child SA indicates that the remote wishes to end the session as a whole.
         * As such, this should not be used in rekey cases where there is any ambiguity as to which
         * Child SA the session is reliant upon.
         *
         * <p>Note that this method will also move the state machine to the closed state.
         */
        protected void handleDeleteSessionRequest(List<IkePayload> payloads) {
            if (!hasRemoteChildSpi(payloads, mCurrentChildSaRecord)) {
                Log.wtf(TAG, "Found no remote SPI for mCurrentChildSaRecord");
                replyErrorNotification(ERROR_TYPE_INVALID_SYNTAX);
                mChildSmCallback.onFatalIkeSessionError(false /*needsNotifyRemote*/);

            } else {
                sendDeleteChild(mCurrentChildSaRecord, true /*isResp*/);

                mChildSmCallback.onChildSaDeleted(mCurrentChildSaRecord.getRemoteSpi());
                mCurrentChildSaRecord.close();
                mCurrentChildSaRecord = null;

                transitionTo(mClosed);
            }
        }
    }

    /**
     * DeleteBase abstracts deletion handling for all states initiating and responding to a Delete
     * Child exchange
     *
     * <p>All subclasses of this state share common functionality that a deletion request is sent,
     * and the response is received.
     */
    private abstract class DeleteBase extends DeleteResponderBase {
        /** Validate payload types in Delete Child response. */
        protected void validateRespPayloadAndExchangeType(
                List<IkePayload> respPayloads, @ExchangeType int exchangeType)
                throws InvalidSyntaxException {

            if (exchangeType != EXCHANGE_TYPE_INFORMATIONAL) {
                throw new InvalidSyntaxException(
                        "Unexpected exchange type in Delete Child response: " + exchangeType);
            }

            for (IkePayload payload : respPayloads) {
                handlePayload:
                switch (payload.payloadType) {
                    case PAYLOAD_TYPE_DELETE:
                        // A Delete Payload is only required when it is not simultaneous deletion.
                        // Included Child SPIs are verified in the subclass to make sure the remote
                        // side is deleting the right SAs.
                        break handlePayload;
                    case PAYLOAD_TYPE_NOTIFY:
                        IkeNotifyPayload notify = (IkeNotifyPayload) payload;
                        if (!notify.isErrorNotify()) {
                            logw(
                                    "Unexpected or unknown status notification in Delete Child"
                                            + " response: "
                                            + notify.notifyType);
                            break handlePayload;
                        }

                        // TODO: Handle error notifications.
                        throw new UnsupportedOperationException(
                                "Cannot handle error notifications in a Delete Child response");
                    default:
                        logw(
                                "Unexpected payload type in Delete Child response: "
                                        + payload.payloadType);
                }
            }
        }
    }

    /**
     * DeleteChildLocalDelete represents the state where Child Session initiates the Delete Child
     * exchange.
     */
    class DeleteChildLocalDelete extends DeleteBase {
        private boolean mSimulDeleteDetected = false;

        @Override
        public void enter() {
            mSimulDeleteDetected = false;
            sendDeleteChild(mCurrentChildSaRecord, false /*isResp*/);
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_HANDLE_RECEIVED_RESPONSE:
                    try {
                        ReceivedResponse resp = (ReceivedResponse) message.obj;
                        validateRespPayloadAndExchangeType(
                                resp.responsePayloads, resp.exchangeType);

                        boolean currentSaSpiFound =
                                hasRemoteChildSpi(resp.responsePayloads, mCurrentChildSaRecord);
                        if (!currentSaSpiFound && !mSimulDeleteDetected) {
                            throw new InvalidSyntaxException(
                                    "Found no remote SPI in received Delete response.");
                        } else if (currentSaSpiFound && mSimulDeleteDetected) {
                            // As required by the RFC 7296, in simultaneous delete case, the remote
                            // side MUST NOT include SPI of mCurrentChildSaRecord. However, to
                            // provide better interoperatibility, IKE library will keep IKE Session
                            // alive and continue the deleting process.
                            logw(
                                    "Found remote SPI in the Delete response in a simultaneous"
                                            + " deletion case");
                        }

                        mChildSmCallback.onChildSaDeleted(mCurrentChildSaRecord.getRemoteSpi());
                        mCurrentChildSaRecord.close();
                        mCurrentChildSaRecord = null;

                        transitionTo(mClosed);
                    } catch (InvalidSyntaxException e) {
                        mChildSmCallback.onFatalIkeSessionError(true /*needsNotifyRemote*/);
                    }
                    return HANDLED;
                case CMD_HANDLE_RECEIVED_REQUEST:
                    ReceivedRequest req = (ReceivedRequest) message.obj;
                    switch (req.exchangeSubtype) {
                        case IKE_EXCHANGE_SUBTYPE_DELETE_CHILD:
                            // It has been verified in IkeSessionStateMachine that the incoming
                            // request can be ONLY for mCurrentChildSaRecord at this point.
                            if (!hasRemoteChildSpi(req.requestPayloads, mCurrentChildSaRecord)) {
                                Log.wtf(TAG, "Found no remote SPI for mCurrentChildSaRecord");

                                replyErrorNotification(ERROR_TYPE_INVALID_SYNTAX);
                                mChildSmCallback.onFatalIkeSessionError(
                                        false /*needsNotifyRemote*/);

                            } else {
                                mChildSmCallback.onOutboundPayloadsReady(
                                        EXCHANGE_TYPE_INFORMATIONAL,
                                        true /*isResp*/,
                                        new LinkedList<>(),
                                        ChildSessionStateMachine.this);
                                mSimulDeleteDetected = true;
                            }
                            return HANDLED;
                        case IKE_EXCHANGE_SUBTYPE_REKEY_CHILD:
                            replyErrorNotification(ERROR_TYPE_TEMPORARY_FAILURE);
                            return HANDLED;
                        default:
                            throw new IllegalArgumentException(
                                    "Invalid exchange subtype for Child Session: "
                                            + req.exchangeSubtype);
                    }
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * DeleteChildRemoteDelete represents the state where Child Session receives the Delete Child
     * request.
     */
    class DeleteChildRemoteDelete extends DeleteResponderBase {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_HANDLE_RECEIVED_REQUEST:
                    ReceivedRequest req = (ReceivedRequest) message.obj;
                    if (req.exchangeSubtype == IKE_EXCHANGE_SUBTYPE_DELETE_CHILD) {
                        handleDeleteSessionRequest(req.requestPayloads);
                        return HANDLED;
                    }
                    return NOT_HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * RekeyChildLocalCreate represents the state where Child Session initiates the Rekey Child
     * exchange.
     *
     * <p>As indicated in RFC 7296 section 2.8, "when rekeying, the new Child SA SHOULD NOT have
     * different Traffic Selectors and algorithms than the old one."
     */
    class RekeyChildLocalCreate extends DeleteResponderBase {
        private List<IkePayload> mRequestPayloads;

        @Override
        public void enter() {
            try {
                // Build request with negotiated proposal and TS.
                mRequestPayloads =
                        CreateChildSaHelper.getRekeyChildCreateReqPayloads(
                                mIpSecManager,
                                mLocalAddress,
                                mSaProposal,
                                mLocalTs,
                                mRemoteTs,
                                mCurrentChildSaRecord.getLocalSpi(),
                                mChildSessionOptions.isTransportMode());
                mChildSmCallback.onOutboundPayloadsReady(
                        EXCHANGE_TYPE_CREATE_CHILD_SA,
                        false /*isResp*/,
                        mRequestPayloads,
                        ChildSessionStateMachine.this);
            } catch (ResourceUnavailableException e) {
                // TODO: Notify users and close the Child Session.
            }
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_HANDLE_RECEIVED_RESPONSE:
                    ReceivedResponse resp = (ReceivedResponse) message.obj;
                    CreateChildResult createChildResult =
                            CreateChildSaHelper.validateAndNegotiateRekeyChildResp(
                                    mRequestPayloads,
                                    resp.responsePayloads,
                                    resp.exchangeType,
                                    EXCHANGE_TYPE_CREATE_CHILD_SA,
                                    mChildSessionOptions.isTransportMode(),
                                    mCurrentChildSaRecord.getRemoteSpi(),
                                    mIpSecManager,
                                    mRemoteAddress);

                    switch (createChildResult.status) {
                        case CREATE_STATUS_OK:
                            try {
                                // Do not need to update the negotiated proposal and TS because they
                                // are not changed.
                                mLocalInitNewChildSaRecord =
                                        ChildSaRecord.makeChildSaRecord(
                                                mContext,
                                                mRequestPayloads,
                                                resp.responsePayloads,
                                                createChildResult.localSpi,
                                                createChildResult.remoteSpi,
                                                mLocalAddress,
                                                mRemoteAddress,
                                                mUdpEncapSocket,
                                                mIkePrf,
                                                mChildIntegrity,
                                                mChildCipher,
                                                mSkD,
                                                mChildSessionOptions.isTransportMode(),
                                                true /*isLocalInit*/);

                                transitionTo(mRekeyChildLocalDelete);
                            } catch (GeneralSecurityException
                                    | ResourceUnavailableException
                                    | SpiUnavailableException
                                    | IOException e) {
                                // #makeChildSaRecord failed.
                                createChildResult.localSpi.close();
                                createChildResult.remoteSpi.close();
                                // TODO: Initiate deletion on newly created SA and retry rekey
                                throw new UnsupportedOperationException("Cannot handle this error");
                            }
                            break;
                        case CREATE_STATUS_CHILD_ERROR_INVALID_MSG:
                            // TODO: Initiate deletion on newly created SA and retry rekey
                            throw new UnsupportedOperationException("Cannot handle this error");
                        case CREATE_STATUS_CHILD_ERROR_RCV_NOTIFY:
                            // TODO: Locally delete newly created Child SA and retry rekey
                            throw new UnsupportedOperationException("Cannot handle this error");
                        case CREATE_STATUS_IKE_ERROR:
                            // TODO: Locally delete newly created Child SA
                            mChildSmCallback.onFatalIkeSessionError(true /*needsNotifyRemote*/);
                            break;
                        default:
                            throw new IllegalArgumentException(
                                    "Unrecognized status: " + createChildResult.status);
                    }
                    return HANDLED;
                default:
                    // TODO: Handle rekey and delete request
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * RekeyChildLocalDelete represents the deleting stage of a locally-initiated Rekey Child
     * procedure.
     */
    class RekeyChildLocalDelete extends State {
        // TODO: Implement it.
    }

    /**
     * Package private helper class to generate IKE SA creation payloads, in both request and
     * response directions.
     */
    static class CreateChildSaHelper {
        /** Create payload list for creating the initial Child SA for this Child Session. */
        public static List<IkePayload> getInitChildCreateReqPayloads(
                IpSecManager ipSecManager,
                InetAddress localAddress,
                ChildSessionOptions childSessionOptions,
                boolean isFirstChild)
                throws ResourceUnavailableException {

            SaProposal[] saProposals = childSessionOptions.getSaProposals();

            if (isFirstChild) {
                for (int i = 0; i < saProposals.length; i++) {
                    saProposals[i] =
                            childSessionOptions.getSaProposals()[i].getCopyWithoutDhTransform();
                }
            }

            return getChildCreatePayloads(
                    ipSecManager,
                    localAddress,
                    saProposals,
                    childSessionOptions.getLocalTrafficSelectors(),
                    childSessionOptions.getRemoteTrafficSelectors(),
                    false /*isResp*/,
                    childSessionOptions.isTransportMode());
        }

        /** Create payload list for creating a new Child SA to rekey this Child Session. */
        public static List<IkePayload> getRekeyChildCreateReqPayloads(
                IpSecManager ipSecManager,
                InetAddress localAddress,
                SaProposal currentProposal,
                IkeTrafficSelector[] currentLocalTs,
                IkeTrafficSelector[] currentRemoteTs,
                int localSpi,
                boolean isTransport)
                throws ResourceUnavailableException {
            List<IkePayload> payloads =
                    getChildCreatePayloads(
                            ipSecManager,
                            localAddress,
                            new SaProposal[] {currentProposal},
                            currentLocalTs,
                            currentRemoteTs,
                            false /*isResp*/,
                            isTransport);

            payloads.add(
                    new IkeNotifyPayload(
                            PROTOCOL_ID_ESP, localSpi, NOTIFY_TYPE_REKEY_SA, new byte[0]));
            return payloads;
        }

        // TODO: Support creating payloads for rekey response by calling #getChildCreatePayloads and
        // adding Notify-Rekey payload.

        /** Create payload list for creating a new Child SA. */
        private static List<IkePayload> getChildCreatePayloads(
                IpSecManager ipSecManager,
                InetAddress localAddress,
                SaProposal[] saProposals,
                IkeTrafficSelector[] initTs,
                IkeTrafficSelector[] respTs,
                boolean isResp,
                boolean isTransport)
                throws ResourceUnavailableException {
            List<IkePayload> payloadList = new ArrayList<>(5);

            payloadList.add(
                    IkeSaPayload.createChildSaRequestPayload(
                            saProposals, ipSecManager, localAddress));
            payloadList.add(new IkeTsPayload(true /*isInitiator*/, initTs));
            payloadList.add(new IkeTsPayload(false /*isInitiator*/, respTs));
            payloadList.add(new IkeNoncePayload());

            DhGroupTransform[] dhGroups = saProposals[0].getDhGroupTransforms();
            if (dhGroups.length != 0 && dhGroups[0].id != DH_GROUP_NONE) {
                payloadList.add(new IkeKePayload(dhGroups[0].id));
            }

            if (isTransport) payloadList.add(new IkeNotifyPayload(NOTIFY_TYPE_USE_TRANSPORT_MODE));

            return payloadList;
        }

        /**
         * Validate the received response of initial Create Child SA exchange and return the
         * negotiation result.
         */
        public static CreateChildResult validateAndNegotiateInitChild(
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                @ExchangeType int exchangeType,
                @ExchangeType int expectedExchangeType,
                boolean expectTransport,
                IpSecManager ipSecManager,
                InetAddress remoteAddress) {

            return validateAndNegotiateChild(
                    reqPayloads,
                    respPayloads,
                    exchangeType,
                    expectedExchangeType,
                    true /*isLocalInit*/,
                    expectTransport,
                    ipSecManager,
                    remoteAddress);
        }

        // TODO: Add method to support validating rekey request

        public static CreateChildResult validateAndNegotiateRekeyChildResp(
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                @ExchangeType int exchangeType,
                @ExchangeType int expectedExchangeType,
                boolean expectTransport,
                int expectedRemoteSpi,
                IpSecManager ipSecManager,
                InetAddress remoteAddress) {
            // Verify Notify-Rekey payload
            List<IkeNotifyPayload> notifyPayloads =
                    IkePayload.getPayloadListForTypeInProvidedList(
                            IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class, respPayloads);

            boolean hasExpectedRekeyNotify = false;
            for (IkeNotifyPayload notifyPayload : notifyPayloads) {
                if (notifyPayload.notifyType == NOTIFY_TYPE_REKEY_SA
                        && notifyPayload.spi == expectedRemoteSpi) {
                    hasExpectedRekeyNotify = true;
                    break;
                }
            }

            if (!hasExpectedRekeyNotify) {
                return new CreateChildResult(
                        CREATE_STATUS_CHILD_ERROR_INVALID_MSG,
                        new InvalidSyntaxException(
                                "Found no Rekey notification with remotely generated IPsec SPI"));
            }

            // Validate rest of payloads and negotiate Child SA.
            CreateChildResult childResult =
                    validateAndNegotiateChild(
                            reqPayloads,
                            respPayloads,
                            exchangeType,
                            expectedExchangeType,
                            true /*isLocalInit*/,
                            expectTransport,
                            ipSecManager,
                            remoteAddress);

            // TODO: Validate new Child SA does not have different Traffic Selectors

            return childResult;
        }

        /** Validate the received response and negotiate Child SA. */
        private static CreateChildResult validateAndNegotiateChild(
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads,
                @ExchangeType int exchangeType,
                @ExchangeType int expectedExchangeType,
                boolean isLocalInit,
                boolean expectTransport,
                IpSecManager ipSecManager,
                InetAddress remoteAddress) {
            List<IkePayload> inboundPayloads = isLocalInit ? respPayloads : reqPayloads;

            try {
                validatePayloadAndExchangeType(
                        inboundPayloads,
                        isLocalInit /*isResp*/,
                        exchangeType,
                        expectedExchangeType);
            } catch (InvalidSyntaxException e) {
                return new CreateChildResult(CREATE_STATUS_IKE_ERROR, e);
            }

            List<IkeNotifyPayload> notifyPayloads =
                    IkePayload.getPayloadListForTypeInProvidedList(
                            IkePayload.PAYLOAD_TYPE_NOTIFY,
                            IkeNotifyPayload.class,
                            inboundPayloads);

            boolean hasTransportNotify = false;
            for (IkeNotifyPayload notify : notifyPayloads) {
                if (notify.isErrorNotify()) {
                    // TODO: Return CreateChildResult with CREATE_STATUS_CHILD_ERROR_RCV_NOTIFY and
                    // IkeProtocolException
                    throw new UnsupportedOperationException("Cannot handle this error");
                }

                switch (notify.notifyType) {
                    case IkeNotifyPayload.NOTIFY_TYPE_ADDITIONAL_TS_POSSIBLE:
                        // TODO: Store it as part of negotiation results that can be retrieved
                        // by users.
                        break;
                    case IkeNotifyPayload.NOTIFY_TYPE_IPCOMP_SUPPORTED:
                        // Ignore
                        break;
                    case IkeNotifyPayload.NOTIFY_TYPE_USE_TRANSPORT_MODE:
                        hasTransportNotify = true;
                        break;
                    case IkeNotifyPayload.NOTIFY_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED:
                        // Ignore
                        break;
                    default:
                        // Unknown and unexpected status notifications are ignored as per RFC7296.
                        Log.w(
                                TAG,
                                "Received unknown or unexpected status notifications with notify"
                                        + " type: "
                                        + notify.notifyType);
                }
            }

            Pair<ChildProposal, ChildProposal> childProposalPair = null;
            try {
                IkeSaPayload reqSaPayload =
                        IkePayload.getPayloadForTypeInProvidedList(
                                IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class, reqPayloads);
                IkeSaPayload respSaPayload =
                        IkePayload.getPayloadForTypeInProvidedList(
                                IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class, respPayloads);

                // This method either throws exception or returns non-null pair that contains two
                // valid {@link ChildProposal} both with a {@link SecurityParameterIndex} allocated
                // inside.
                childProposalPair =
                        IkeSaPayload.getVerifiedNegotiatedChildProposalPair(
                                reqSaPayload, respSaPayload, ipSecManager, remoteAddress);
                SaProposal saProposal = childProposalPair.second.saProposal;

                validateKePayloads(inboundPayloads, isLocalInit /*isResp*/, saProposal);

                if (expectTransport != hasTransportNotify) {
                    throw new NoValidProposalChosenException(
                            "Failed the negotiation on Child SA mode (conflicting modes chosen).");
                }

                Pair<IkeTrafficSelector[], IkeTrafficSelector[]> tsPair =
                        validateAndGetNegotiatedTsPair(
                                reqPayloads, respPayloads, true /*isLocalInit*/);

                return new CreateChildResult(
                        childProposalPair.first.getChildSpiResource(),
                        childProposalPair.second.getChildSpiResource(),
                        saProposal,
                        tsPair.first,
                        tsPair.second);
            } catch (IkeProtocolException
                    | ResourceUnavailableException
                    | SpiUnavailableException e) {
                if (childProposalPair != null) {
                    childProposalPair.first.getChildSpiResource().close();
                    childProposalPair.second.getChildSpiResource().close();
                }

                if (e instanceof IkeProtocolException) {
                    int errorStatus =
                            (e instanceof InvalidSyntaxException)
                                    ? CREATE_STATUS_IKE_ERROR
                                    : CREATE_STATUS_CHILD_ERROR_INVALID_MSG;
                    return new CreateChildResult(errorStatus, (IkeProtocolException) e);
                } else {
                    return new CreateChildResult(
                            CREATE_STATUS_CHILD_ERROR_INVALID_MSG, new IkeInternalException(e));
                }
            }
        }

        private static void validatePayloadAndExchangeType(
                List<IkePayload> inboundPayloads,
                boolean isResp,
                @ExchangeType int exchangeType,
                @ExchangeType int expectedExchangeType)
                throws InvalidSyntaxException {
            boolean hasSaPayload = false;
            boolean hasKePayload = false;
            boolean hasNoncePayload = false;
            boolean hasTsInitPayload = false;
            boolean hasTsRespPayload = false;

            for (IkePayload payload : inboundPayloads) {
                switch (payload.payloadType) {
                    case PAYLOAD_TYPE_SA:
                        hasSaPayload = true;
                        break;
                    case PAYLOAD_TYPE_KE:
                        // Could not decide if KE Payload MUST or MUST NOT be included until SA
                        // negotiation is done.
                        hasKePayload = true;
                        break;
                    case PAYLOAD_TYPE_NONCE:
                        hasNoncePayload = true;
                        break;
                    case PAYLOAD_TYPE_TS_INITIATOR:
                        hasTsInitPayload = true;
                        break;
                    case PAYLOAD_TYPE_TS_RESPONDER:
                        hasTsRespPayload = true;
                        break;
                    case PAYLOAD_TYPE_NOTIFY:
                        IkeNotifyPayload notifyPayload = (IkeNotifyPayload) payload;

                        if (notifyPayload.isErrorNotify() && !isResp) {
                            Log.w(
                                    TAG,
                                    "Received error notification in a Create Child SA request: "
                                            + notifyPayload.notifyType);
                        }
                        break;
                    default:
                        Log.w(
                                TAG,
                                "Received unexpected payload in Create Child SA message. Payload"
                                        + " type: "
                                        + payload.payloadType);
                }
            }

            // Do not need to check exchange type of a request because it has been already verified
            // in IkeSessionStateMachine
            if (isResp
                    && exchangeType != expectedExchangeType
                    && exchangeType != EXCHANGE_TYPE_INFORMATIONAL) {
                throw new InvalidSyntaxException("Received invalid exchange type: " + exchangeType);
            }

            if (exchangeType == EXCHANGE_TYPE_INFORMATIONAL
                    && (hasSaPayload
                            || hasKePayload
                            || hasNoncePayload
                            || hasTsInitPayload
                            || hasTsRespPayload)) {
                Log.w(
                        TAG,
                        "Unexpected payload found in an INFORMATIONAL message: SA, KE, Nonce,"
                                + " TS-Initiator or TS-Responder");
            }

            if (!hasSaPayload || !hasNoncePayload || !hasTsInitPayload || !hasTsRespPayload) {
                throw new InvalidSyntaxException(
                        "SA, Nonce, TS-Initiator or TS-Responder missing.");
            }
        }

        private static Pair<IkeTrafficSelector[], IkeTrafficSelector[]>
                validateAndGetNegotiatedTsPair(
                        List<IkePayload> reqPayloads,
                        List<IkePayload> respPayloads,
                        boolean isLocalInit)
                        throws TsUnacceptableException {
            IkeTrafficSelector[] initTs =
                    validateAndGetNegotiatedTs(reqPayloads, respPayloads, true /*isInitTs*/);
            IkeTrafficSelector[] respTs =
                    validateAndGetNegotiatedTs(reqPayloads, respPayloads, false /*isInitTs*/);

            if (isLocalInit) {
                return new Pair<IkeTrafficSelector[], IkeTrafficSelector[]>(initTs, respTs);
            } else {
                return new Pair<IkeTrafficSelector[], IkeTrafficSelector[]>(respTs, initTs);
            }
        }

        private static IkeTrafficSelector[] validateAndGetNegotiatedTs(
                List<IkePayload> reqPayloads, List<IkePayload> respPayloads, boolean isInitTs)
                throws TsUnacceptableException {
            int tsType = isInitTs ? PAYLOAD_TYPE_TS_INITIATOR : PAYLOAD_TYPE_TS_RESPONDER;
            IkeTsPayload reqPayload =
                    IkePayload.getPayloadForTypeInProvidedList(
                            tsType, IkeTsPayload.class, reqPayloads);
            IkeTsPayload respPayload =
                    IkePayload.getPayloadForTypeInProvidedList(
                            tsType, IkeTsPayload.class, respPayloads);

            if (!reqPayload.contains(respPayload)) {
                throw new TsUnacceptableException();
            }

            // It is guaranteed by decoding inbound TS Payload and constructing outbound TS Payload
            // that each TS Payload has at least one IkeTrafficSelector.
            return respPayload.trafficSelectors;
        }

        @VisibleForTesting
        static void validateKePayloads(
                List<IkePayload> inboundPayloads, boolean isResp, SaProposal negotiatedProposal)
                throws IkeProtocolException {
            DhGroupTransform[] dhTransforms = negotiatedProposal.getDhGroupTransforms();

            if (dhTransforms.length > 1) {
                throw new IllegalArgumentException(
                        "Found multiple DH Group Transforms in the negotiated SA proposal");
            }
            boolean expectKePayload =
                    dhTransforms.length == 1 && dhTransforms[0].id != DH_GROUP_NONE;

            IkeKePayload kePayload =
                    IkePayload.getPayloadForTypeInProvidedList(
                            PAYLOAD_TYPE_KE, IkeKePayload.class, inboundPayloads);

            if (expectKePayload && (kePayload == null || dhTransforms[0].id != kePayload.dhGroup)) {
                if (isResp) {
                    throw new InvalidSyntaxException(
                            "KE Payload missing or has mismatched DH Group with the negotiated"
                                    + " proposal.");
                } else {
                    throw new InvalidKeException(dhTransforms[0].id);
                }

            } else if (!expectKePayload && kePayload != null && isResp) {
                // It is valid when the remote request proposed multiple DH Groups with a KE
                // payload, and the responder chose DH_GROUP_NONE.
                throw new InvalidSyntaxException("Received unexpected KE Payload.");
            }
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        CREATE_STATUS_OK,
        CREATE_STATUS_CHILD_ERROR_INVALID_MSG,
        CREATE_STATUS_CHILD_ERROR_RCV_NOTIFY,
        CREATE_STATUS_IKE_ERROR
    })
    @interface CreateStatus {}

    /** The Child SA negotiation succeeds. */
    private static final int CREATE_STATUS_OK = 0;
    /** The inbound message is invalid in Child negotiation but is non-fatal for IKE Session. */
    private static final int CREATE_STATUS_CHILD_ERROR_INVALID_MSG = 1;
    /** The inbound message includes error notification that failed the Child negotiation. */
    private static final int CREATE_STATUS_CHILD_ERROR_RCV_NOTIFY = 2;
    /** The inbound message has fatal error that causes IKE library to close the IKE Session. */
    private static final int CREATE_STATUS_IKE_ERROR = 3;

    private static class CreateChildResult {
        @CreateStatus public final int status;
        public final SecurityParameterIndex localSpi;
        public final SecurityParameterIndex remoteSpi;
        public final SaProposal negotiatedProposal;
        public final IkeTrafficSelector[] localTs;
        public final IkeTrafficSelector[] remoteTs;
        public final IkeException exception;

        private CreateChildResult(
                @CreateStatus int status,
                SecurityParameterIndex localSpi,
                SecurityParameterIndex remoteSpi,
                SaProposal negotiatedProposal,
                IkeTrafficSelector[] localTs,
                IkeTrafficSelector[] remoteTs,
                IkeException exception) {
            this.status = status;
            this.localSpi = localSpi;
            this.remoteSpi = remoteSpi;
            this.negotiatedProposal = negotiatedProposal;
            this.localTs = localTs;
            this.remoteTs = remoteTs;
            this.exception = exception;
        }

        /* Construct a CreateChildResult instance for a successful case. */
        CreateChildResult(
                SecurityParameterIndex localSpi,
                SecurityParameterIndex remoteSpi,
                SaProposal negotiatedProposal,
                IkeTrafficSelector[] localTs,
                IkeTrafficSelector[] remoteTs) {
            this(
                    CREATE_STATUS_OK,
                    localSpi,
                    remoteSpi,
                    negotiatedProposal,
                    localTs,
                    remoteTs,
                    null /*exception*/);
        }

        /** Construct a CreateChildResult instance for an error case. */
        CreateChildResult(@CreateStatus int status, IkeException exception) {
            this(
                    status,
                    null /*localSpi*/,
                    null /*remoteSpi*/,
                    null /*negotiatedProposal*/,
                    null /*localTs*/,
                    null /*remoteTs*/,
                    exception);
        }
    }

    /** Called when this StateMachine quits. */
    @Override
    protected void onQuitting() {
        mChildSmCallback.onProcedureFinished(ChildSessionStateMachine.this);
        mChildSmCallback.onChildSessionClosed(mUserCallback);
    }

    // TODO: Add states to support deleting Child SA and rekeying Child SA.
}
