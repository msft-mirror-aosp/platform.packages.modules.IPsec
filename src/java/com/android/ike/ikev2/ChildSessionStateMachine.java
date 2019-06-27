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
import static com.android.ike.ikev2.SaProposal.DH_GROUP_NONE;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_IKE_AUTH;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_INFORMATIONAL;
import static com.android.ike.ikev2.message.IkeHeader.ExchangeType;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_USE_TRANSPORT_MODE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_DELETE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_KE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NONCE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_SA;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_TS_INITIATOR;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_TS_RESPONDER;

import android.annotation.IntDef;
import android.annotation.Nullable;
import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.SecurityParameterIndex;
import android.net.IpSecManager.SpiUnavailableException;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.util.Pair;

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

    /** Callback to notify IKE Session the state changes. */
    private final IChildSessionSmCallback mChildSmCallback;

    // TODO: Also store ChildSessionCallback for notifying users.

    /** Local address assigned on device. */
    private final InetAddress mLocalAddress;
    /** Remote address configured by users. */
    private final InetAddress mRemoteAddress;

    /**
     * UDP-Encapsulated socket that allows IPsec traffic to pass through a NAT. Null if UDP
     * encapsulation is not needed.
     */
    @Nullable private final UdpEncapsulationSocket mUdpEncapSocket;

    private final IkeMacPrf mIkePrf;

    /** Package private SaProposal that represents the negotiated Child SA proposal. */
    @VisibleForTesting SaProposal mSaProposal;

    /** Negotiated local Traffic Selector. */
    @VisibleForTesting IkeTrafficSelector[] mLocalTs;
    /** Negotiated remote Traffic Selector. */
    @VisibleForTesting IkeTrafficSelector[] mRemoteTs;

    private IkeCipher mChildCipher;
    private IkeMacIntegrity mChildIntegrity;

    /** SK_d is renewed when IKE SA is rekeyed. */
    private byte[] mSkD;

    /** Package private */
    @VisibleForTesting ChildSaRecord mCurrentChildSaRecord;

    @VisibleForTesting final State mInitial = new Initial();
    @VisibleForTesting final State mCreateChildLocalCreate = new CreateChildLocalCreate();
    @VisibleForTesting final State mClosed = new Closed();
    @VisibleForTesting final State mIdle = new Idle();
    @VisibleForTesting final State mDeleteChildLocalDelete = new DeleteChildLocalDelete();

    /** Package private */
    ChildSessionStateMachine(
            Looper looper,
            Context context,
            IpSecManager ipSecManager,
            ChildSessionOptions sessionOptions,
            IChildSessionSmCallback childSmCallback,
            InetAddress localAddress,
            InetAddress remoteAddress,
            UdpEncapsulationSocket udpEncapSocket,
            IkeMacPrf ikePrf,
            byte[] skD) {
        super(TAG, looper);

        mContext = context;
        mIpSecManager = ipSecManager;

        mChildSessionOptions = sessionOptions;
        mChildSmCallback = childSmCallback;

        mLocalAddress = localAddress;
        mRemoteAddress = remoteAddress;
        mUdpEncapSocket = udpEncapSocket;
        mIkePrf = ikePrf;
        mSkD = skD;

        addState(mInitial);
        addState(mCreateChildLocalCreate);
        addState(mClosed);
        addState(mIdle);
        addState(mDeleteChildLocalDelete);

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
                @ExchangeType int exchangeType, boolean isResp, List<IkePayload> payloadList);

        /** Notify that a Child procedure has been finished. */
        void onProcedureFinished(ChildSessionStateMachine childSession);

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
     */
    public void handleFirstChildExchange(
            List<IkePayload> reqPayloads, List<IkePayload> respPayloads) {
        registerProvisionalChildSession(respPayloads);

        sendMessage(
                CMD_HANDLE_FIRST_CHILD_EXCHANGE,
                new FirstChildNegotiationData(reqPayloads, respPayloads));
    }

    /**
     * Initiate Create Child procedure.
     *
     * <p>This method is called synchronously from IkeStateMachine. It proxies the synchronous call
     * as an asynchronous job to the ChildStateMachine handler.
     */
    public void createChildSession() {
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

    // TODO: Add receiveRequest() and rekeyChildSession()

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
        // TODO: Also check if Child Session is waiting for Rekey Create response.
        return getCurrentState() == mCreateChildLocalCreate;
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
                        CreateChildSaHelper.getInitCreateSaRequestPayloads(
                                mIpSecManager,
                                mLocalAddress,
                                mChildSessionOptions,
                                false /*isFirstChild*/);
                mChildSmCallback.onOutboundPayloadsReady(
                        EXCHANGE_TYPE_CREATE_CHILD_SA, false /*isResp*/, mRequestPayloads);
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
                    EXCHANGE_TYPE_INFORMATIONAL, isResp, outIkePayloads);
        }

        // TODO: Add a method to handle an inbound Child Session deletion request
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
        // TODO: Support simultaneous deletion and reply TEMPORARY_FAILURE to other requests.
        @Override
        public void enter() {
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
                        if (!currentSaSpiFound) {
                            throw new InvalidSyntaxException(
                                    "Found no remote SPI in received Delete response.");
                        }

                        mChildSmCallback.onChildSaDeleted(mCurrentChildSaRecord.getRemoteSpi());
                        mCurrentChildSaRecord.close();
                        mCurrentChildSaRecord = null;

                        transitionTo(mClosed);
                    } catch (InvalidSyntaxException e) {
                        mChildSmCallback.onFatalIkeSessionError(true /*needsNotifyRemote*/);
                    }
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Package private helper class to generate IKE SA creation payloads, in both request and
     * response directions.
     */
    static class CreateChildSaHelper {
        /** Create payload list for creating the initial Child SA for this Child Session. */
        public static List<IkePayload> getInitCreateSaRequestPayloads(
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

            return getCreateSaPayloads(
                    ipSecManager,
                    localAddress,
                    saProposals,
                    childSessionOptions.getLocalTrafficSelectors(),
                    childSessionOptions.getRemoteTrafficSelectors(),
                    false /*isResp*/,
                    childSessionOptions.isTransportMode());
        }

        // TODO: Support creating payloads for rekey request and response by calling
        // #getCreateSaPayloads and adding Notify-Rekey payload.

        /** Create payload list for creating a new Child SA. */
        private static List<IkePayload> getCreateSaPayloads(
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
                    IkeSaPayload.createChildSaPayload(
                            isResp, saProposals, ipSecManager, localAddress));
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

        // TODO: Add method to support validating rekey request and response

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
                        respSaPayload.getVerifiedNegotiatedChildProposalPair(
                                reqSaPayload, ipSecManager, remoteAddress);
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

                        if (notifyPayload.isErrorNotify()) {
                            if (!isResp) {
                                throw new InvalidSyntaxException(
                                        "Received error notification in a Create Child SA request");
                            }
                        }
                        break;
                    default:
                        throw new InvalidSyntaxException(
                                "Received unexpected payload in Create Child SA request. Payload"
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
                throw new InvalidSyntaxException(
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
    }

    // TODO: Add states to support deleting Child SA and rekeying Child SA.
}
