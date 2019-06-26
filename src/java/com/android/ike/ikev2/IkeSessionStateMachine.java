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

import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_MAJOR_VERSION;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_SYNTAX;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_OK;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_PROTECTED_ERROR_MESSAGE;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_CP;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_VENDOR;

import android.annotation.IntDef;
import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.os.Looper;
import android.os.Message;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import android.util.LongSparseArray;
import android.util.Pair;
import android.util.SparseArray;

import com.android.ike.ikev2.ChildSessionStateMachine.CreateChildSaHelper;
import com.android.ike.ikev2.IkeLocalRequestScheduler.ChildLocalRequest;
import com.android.ike.ikev2.IkeLocalRequestScheduler.LocalRequest;
import com.android.ike.ikev2.IkeSessionOptions.IkeAuthConfig;
import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.exceptions.AuthenticationFailedException;
import com.android.ike.ikev2.exceptions.IkeProtocolException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.message.IkeAuthPayload;
import com.android.ike.ikev2.message.IkeAuthPskPayload;
import com.android.ike.ikev2.message.IkeCertPayload;
import com.android.ike.ikev2.message.IkeDeletePayload;
import com.android.ike.ikev2.message.IkeHeader;
import com.android.ike.ikev2.message.IkeHeader.ExchangeType;
import com.android.ike.ikev2.message.IkeIdPayload;
import com.android.ike.ikev2.message.IkeInformationalPayload;
import com.android.ike.ikev2.message.IkeKePayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeMessage.DecodeResult;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkeNotifyPayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.ike.ikev2.message.IkeSaPayload;
import com.android.ike.ikev2.message.IkeSaPayload.DhGroupTransform;
import com.android.ike.ikev2.message.IkeSaPayload.IkeProposal;
import com.android.ike.ikev2.message.IkeTsPayload;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import dalvik.system.CloseGuard;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * IkeSessionStateMachine tracks states and manages exchanges of this IKE session.
 *
 * <p>IkeSessionStateMachine has two types of states. One type are states where there is no ongoing
 * procedure affecting IKE session (non-procedure state), including Initial, Closed, Idle and
 * Receiving. All other states are "procedure" states which are named as follows:
 *
 * <pre>
 * State Name = [Procedure Type] + [Exchange Initiator] + [Exchange Type].
 * - An IKE procedure consists of one or two IKE exchanges:
 *      Procedure Type = {CreateIke | DeleteIke | Info | RekeyIke | SimulRekeyIke}.
 * - Exchange Initiator indicates whether local or remote peer is the exchange initiator:
 *      Exchange Initiator = {Local | Remote}
 * - Exchange type defines the function of this exchange. To make it more descriptive, we separate
 *      Delete Exchange from generic Informational Exchange:
 *      Exchange Type = {IkeInit | IkeAuth | Create | Delete | Info}
 * </pre>
 */
public class IkeSessionStateMachine extends StateMachine {

    private static final String TAG = "IkeSessionStateMachine";

    // Use a value greater than the retransmit-failure timeout.
    static final long REKEY_DELETE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(180L);

    // Package private IKE exchange subtypes describe the specific function of a IKE
    // request/response exchange. It helps IkeSessionStateMachine to do message validation according
    // to the subtype specific rules.
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        IKE_EXCHANGE_SUBTYPE_INVALID,
        IKE_EXCHANGE_SUBTYPE_IKE_INIT,
        IKE_EXCHANGE_SUBTYPE_IKE_AUTH,
        IKE_EXCHANGE_SUBTYPE_DELETE_IKE,
        IKE_EXCHANGE_SUBTYPE_DELETE_CHILD,
        IKE_EXCHANGE_SUBTYPE_REKEY_IKE,
        IKE_EXCHANGE_SUBTYPE_REKEY_CHILD,
        IKE_EXCHANGE_SUBTYPE_GENERIC_INFO
    })
    @interface IkeExchangeSubType {}

    static final int IKE_EXCHANGE_SUBTYPE_INVALID = 0;
    static final int IKE_EXCHANGE_SUBTYPE_IKE_INIT = 1;
    static final int IKE_EXCHANGE_SUBTYPE_IKE_AUTH = 2;
    static final int IKE_EXCHANGE_SUBTYPE_CREATE_CHILD = 3;
    static final int IKE_EXCHANGE_SUBTYPE_DELETE_IKE = 4;
    static final int IKE_EXCHANGE_SUBTYPE_DELETE_CHILD = 5;
    static final int IKE_EXCHANGE_SUBTYPE_REKEY_IKE = 6;
    static final int IKE_EXCHANGE_SUBTYPE_REKEY_CHILD = 7;
    static final int IKE_EXCHANGE_SUBTYPE_GENERIC_INFO = 8;

    private static final int CHILD_PAYLOADS_DIRECTION_REQUEST = 0;
    private static final int CHILD_PAYLOADS_DIRECTION_RESPONSE = 1;

    /** Package private signals accessible for testing code. */
    private static final int CMD_GENERAL_BASE = 0;

    private static final int CMD_CATEGORY_SIZE = 100;
    /** Receive encoded IKE packet on IkeSessionStateMachine. */
    static final int CMD_RECEIVE_IKE_PACKET = CMD_GENERAL_BASE + 1;
    /** Receive encoded IKE packet with unrecognized IKE SPI on IkeSessionStateMachine. */
    static final int CMD_RECEIVE_PACKET_INVALID_IKE_SPI = CMD_GENERAL_BASE + 2;
    /** Receive an remote request for a Child procedure. */
    static final int CMD_RECEIVE_REQUEST_FOR_CHILD = CMD_GENERAL_BASE + 3;
    /** Receive payloads from Child Session for building an outbound IKE message. */
    static final int CMD_OUTBOUND_CHILD_PAYLOADS_READY = CMD_GENERAL_BASE + 4;
    /** A Child Session has finished its procedure. */
    static final int CMD_CHILD_PROCEDURE_FINISHED = CMD_GENERAL_BASE + 5;
    /** Send request/response payloads to ChildSessionStateMachine for further processing. */
    static final int CMD_HANDLE_FIRST_CHILD_NEGOTIATION = CMD_GENERAL_BASE + 6;
    /** Receive a local request to execute from the scheduler */
    static final int CMD_EXECUTE_LOCAL_REQ = CMD_GENERAL_BASE + 7;
    /** Force state machine to a target state for testing purposes. */
    static final int CMD_FORCE_TRANSITION = CMD_GENERAL_BASE + 99;
    // TODO: Add signal for retransmission.

    // Constants for local request will be used in both IkeSessionStateMachine and
    // ChildSessionStateMachine.
    private static final int CMD_LOCAL_REQUEST_BASE = CMD_GENERAL_BASE + CMD_CATEGORY_SIZE;
    static final int CMD_LOCAL_REQUEST_CREATE_IKE = CMD_LOCAL_REQUEST_BASE + 1;
    static final int CMD_LOCAL_REQUEST_DELETE_IKE = CMD_LOCAL_REQUEST_BASE + 2;
    static final int CMD_LOCAL_REQUEST_REKEY_IKE = CMD_LOCAL_REQUEST_BASE + 3;
    static final int CMD_LOCAL_REQUEST_INFO = CMD_LOCAL_REQUEST_BASE + 4;
    static final int CMD_LOCAL_REQUEST_CREATE_CHILD = CMD_LOCAL_REQUEST_BASE + 5;
    static final int CMD_LOCAL_REQUEST_DELETE_CHILD = CMD_LOCAL_REQUEST_BASE + 6;
    static final int CMD_LOCAL_REQUEST_REKEY_CHILD = CMD_LOCAL_REQUEST_BASE + 7;
    // TODO: Add signals for other procedure types and notificaitons.

    private static final int TIMEOUT_BASE = CMD_GENERAL_BASE + 200;
    static final int TIMEOUT_REKEY_REMOTE_DELETE_IKE = TIMEOUT_BASE + 1;

    private final IkeSessionOptions mIkeSessionOptions;

    /** Map that stores all IkeSaRecords, keyed by remotely generated IKE SPI. */
    private final LongSparseArray<IkeSaRecord> mSpiToSaRecordMap;
    /**
     * Map that stores all ChildSessionStateMachines, keyed by remotely generated Child SPI for
     * sending IPsec packet. Different SPIs may point to the same ChildSessionStateMachine if this
     * Child Session is doing Rekey.
     */
    private final SparseArray<ChildSessionStateMachine> mSpiToChildSessionMap;

    private final Context mContext;
    private final IpSecManager mIpSecManager;
    private final IkeLocalRequestScheduler mScheduler;

    /**
     * Package private socket that sends and receives encoded IKE message. Initialized in Initial
     * State.
     */
    @VisibleForTesting IkeSocket mIkeSocket;

    /** Local address assigned on device. Initialized in Initial State. */
    @VisibleForTesting InetAddress mLocalAddress;
    /** Remote address configured by users. Initialized in Initial State. */
    @VisibleForTesting InetAddress mRemoteAddress;
    /** Local port assigned on device. Initialized in Initial State. */
    @VisibleForTesting int mLocalPort;

    /** Indicates if local node is behind a NAT. */
    @VisibleForTesting boolean mIsLocalBehindNat;
    /** Indicates if remote node is behind a NAT. */
    @VisibleForTesting boolean mIsRemoteBehindNat;

    /** Package private SaProposal that represents the negotiated IKE SA proposal. */
    @VisibleForTesting SaProposal mSaProposal;

    @VisibleForTesting IkeCipher mIkeCipher;
    @VisibleForTesting IkeMacIntegrity mIkeIntegrity;
    @VisibleForTesting IkeMacPrf mIkePrf;

    // FIXME: b/131265898 Pass these parameters from CreateIkeLocalIkeInit to CreateIkeLocalIkeAuth
    // as entry data when Android StateMachine can support that.
    @VisibleForTesting byte[] mIkeInitRequestBytes;
    @VisibleForTesting byte[] mIkeInitResponseBytes;
    @VisibleForTesting IkeNoncePayload mIkeInitNoncePayload;
    @VisibleForTesting IkeNoncePayload mIkeRespNoncePayload;

    /** Package */
    @VisibleForTesting IkeSaRecord mCurrentIkeSaRecord;
    /** Package */
    @VisibleForTesting IkeSaRecord mLocalInitNewIkeSaRecord;
    /** Package */
    @VisibleForTesting IkeSaRecord mRemoteInitNewIkeSaRecord;

    /** Package */
    @VisibleForTesting IkeSaRecord mIkeSaRecordSurviving;
    /** Package */
    @VisibleForTesting IkeSaRecord mIkeSaRecordAwaitingLocalDel;
    /** Package */
    @VisibleForTesting IkeSaRecord mIkeSaRecordAwaitingRemoteDel;

    // States
    @VisibleForTesting final State mInitial = new Initial();
    @VisibleForTesting final State mClosed = new Closed();
    @VisibleForTesting final State mIdle = new Idle();
    @VisibleForTesting final State mChildProcedureOngoing = new ChildProcedureOngoing();
    @VisibleForTesting final State mReceiving = new Receiving();
    @VisibleForTesting final State mCreateIkeLocalIkeInit = new CreateIkeLocalIkeInit();
    @VisibleForTesting final State mCreateIkeLocalIkeAuth = new CreateIkeLocalIkeAuth();
    @VisibleForTesting final State mRekeyIkeLocalCreate = new RekeyIkeLocalCreate();
    @VisibleForTesting final State mSimulRekeyIkeLocalCreate = new SimulRekeyIkeLocalCreate();

    @VisibleForTesting
    final State mSimulRekeyIkeLocalDeleteRemoteDelete = new SimulRekeyIkeLocalDeleteRemoteDelete();

    @VisibleForTesting final State mSimulRekeyIkeLocalDelete = new SimulRekeyIkeLocalDelete();
    @VisibleForTesting final State mSimulRekeyIkeRemoteDelete = new SimulRekeyIkeRemoteDelete();
    @VisibleForTesting final State mRekeyIkeLocalDelete = new RekeyIkeLocalDelete();
    @VisibleForTesting final State mRekeyIkeRemoteDelete = new RekeyIkeRemoteDelete();
    @VisibleForTesting final State mDeleteIkeLocalDelete = new DeleteIkeLocalDelete();
    // TODO: Add InfoLocal.

    /** Package private constructor */
    IkeSessionStateMachine(
            Looper looper,
            Context context,
            IpSecManager ipSecManager,
            IkeSessionOptions ikeOptions,
            ChildSessionOptions firstChildOptions) {
        super(TAG, looper);

        mIkeSessionOptions = ikeOptions;

        // There are at most three IkeSaRecords co-existing during simultaneous rekeying.
        mSpiToSaRecordMap = new LongSparseArray<>(3);
        mSpiToChildSessionMap = new SparseArray<>();

        mContext = context;
        mIpSecManager = ipSecManager;

        ((CreateIkeLocalIkeAuth) mCreateIkeLocalIkeAuth).initializeAuthParams(firstChildOptions);

        addState(mInitial);
        addState(mClosed);
        addState(mCreateIkeLocalIkeInit);
        addState(mCreateIkeLocalIkeAuth);
        addState(mIdle);
        addState(mChildProcedureOngoing);
        addState(mReceiving);
        addState(mRekeyIkeLocalCreate);
        addState(mSimulRekeyIkeLocalCreate, mRekeyIkeLocalCreate);
        addState(mSimulRekeyIkeLocalDeleteRemoteDelete);
        addState(mSimulRekeyIkeLocalDelete, mSimulRekeyIkeLocalDeleteRemoteDelete);
        addState(mSimulRekeyIkeRemoteDelete, mSimulRekeyIkeLocalDeleteRemoteDelete);
        addState(mRekeyIkeLocalDelete);
        addState(mRekeyIkeRemoteDelete);
        addState(mDeleteIkeLocalDelete);

        setInitialState(mInitial);
        mScheduler =
                new IkeLocalRequestScheduler(
                        localReq -> {
                            sendMessageAtFrontOfQueue(CMD_EXECUTE_LOCAL_REQ, localReq);
                        });
        // TODO: Start the StateMachine.
    }

    // TODO: Add interfaces to initiate IKE exchanges.

    /**
     * This class represents a reserved IKE SPI.
     *
     * <p>This class is created to avoid assigning same SPI to the same address.
     *
     * <p>Objects of this type are used to track reserved IKE SPI to avoid SPI collision. They can
     * be obtained by calling {@link #allocateSecurityParameterIndex()} and must be released by
     * calling {@link #close()} when they are no longer needed.
     *
     * <p>This class follows the pattern of {@link IpSecManager.SecurityParameterIndex}.
     *
     * <p>TODO: Move this class to a central place, like IkeManager.
     */
    public static final class IkeSecurityParameterIndex implements AutoCloseable {
        // Remember assigned IKE SPIs to avoid SPI collision.
        private static final Set<Pair<InetAddress, Long>> sAssignedIkeSpis = new HashSet<>();
        private static final int MAX_ASSIGN_IKE_SPI_ATTEMPTS = 100;
        private static final SecureRandom IKE_SPI_RANDOM = new SecureRandom();

        private final InetAddress mSourceAddress;
        private final long mSpi;
        private final CloseGuard mCloseGuard = CloseGuard.get();

        private IkeSecurityParameterIndex(InetAddress sourceAddress, long spi) {
            mSourceAddress = sourceAddress;
            mSpi = spi;
            mCloseGuard.open("close");
        }

        /**
         * Get a new IKE SPI and maintain the reservation.
         *
         * @return an instance of IkeSecurityParameterIndex.
         */
        public static IkeSecurityParameterIndex allocateSecurityParameterIndex(
                InetAddress sourceAddress) throws IOException {
            // TODO: Create specific Exception for SPI assigning error.

            for (int i = 0; i < MAX_ASSIGN_IKE_SPI_ATTEMPTS; i++) {
                long spi = IKE_SPI_RANDOM.nextLong();
                // Zero value can only be used in the IKE responder SPI field of an IKE INIT
                // request.
                if (spi != 0L
                        && sAssignedIkeSpis.add(new Pair<InetAddress, Long>(sourceAddress, spi))) {
                    return new IkeSecurityParameterIndex(sourceAddress, spi);
                }
            }

            throw new IOException("Failed to generate IKE SPI.");
        }

        /**
         * Get a new IKE SPI and maintain the reservation.
         *
         * @return an instance of IkeSecurityParameterIndex.
         */
        public static IkeSecurityParameterIndex allocateSecurityParameterIndex(
                InetAddress sourceAddress, long requestedSpi) throws IOException {
            if (sAssignedIkeSpis.add(new Pair<InetAddress, Long>(sourceAddress, requestedSpi))) {
                return new IkeSecurityParameterIndex(sourceAddress, requestedSpi);
            }

            throw new IOException("Failed to generate IKE SPI.");
        }

        /**
         * Get the underlying SPI held by this object.
         *
         * @return the underlying IKE SPI.
         */
        public long getSpi() {
            return mSpi;
        }

        /** Release an SPI that was previously reserved. */
        @Override
        public void close() {
            sAssignedIkeSpis.remove(new Pair<InetAddress, Long>(mSourceAddress, mSpi));
            mCloseGuard.close();
        }

        /** Check that the IkeSecurityParameterIndex was closed properly. */
        @Override
        protected void finalize() throws Throwable {
            if (mCloseGuard != null) {
                mCloseGuard.warnIfOpen();
            }
            close();
        }
    }

    // TODO: Add methods for building and validating general Informational packet.

    @VisibleForTesting
    void addIkeSaRecord(IkeSaRecord record) {
        // TODO: We register local SPI in IkeSocket. For consistency we should also use local IKE
        // SPI here.
        mSpiToSaRecordMap.put(record.getRemoteSpi(), record);
    }

    @VisibleForTesting
    void removeIkeSaRecord(IkeSaRecord record) {
        mSpiToSaRecordMap.remove(record.getRemoteSpi());
    }

    /**
     * Receive IKE packet from remote server.
     *
     * <p>This method is called synchronously from IkeSocket. It proxies the synchronous call as an
     * asynchronous job to the IkeSessionStateMachine handler.
     *
     * @param ikeHeader the decoded IKE header.
     * @param ikePacketBytes the byte array of the entire received IKE packet.
     */
    public void receiveIkePacket(IkeHeader ikeHeader, byte[] ikePacketBytes) {
        sendMessage(CMD_RECEIVE_IKE_PACKET, new ReceivedIkePacket(ikeHeader, ikePacketBytes));
    }

    /**
     * ReceivedIkePacket is a package private data container consists of decoded IkeHeader and
     * encoded IKE packet in a byte array.
     */
    static class ReceivedIkePacket {
        /** Decoded IKE header */
        public final IkeHeader ikeHeader;
        /** Entire encoded IKE message including IKE header */
        public final byte[] ikePacketBytes;

        ReceivedIkePacket(IkeHeader ikeHeader, byte[] ikePacketBytes) {
            this.ikeHeader = ikeHeader;
            this.ikePacketBytes = ikePacketBytes;
        }
    }

    /** Class to group parameters for negotiating the first Child SA. */
    private static class FirstChildNegotiationData {
        public final ChildSessionOptions childSessionOptions;
        public final List<IkePayload> reqPayloads;
        public final List<IkePayload> respPayloads;

        // TODO: Also store ChildSessionCallback

        FirstChildNegotiationData(
                ChildSessionOptions childSessionOptions,
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads) {
            this.childSessionOptions = childSessionOptions;
            this.reqPayloads = reqPayloads;
            this.respPayloads = respPayloads;
        }
    }

    /** Callback for ChildSessionStateMachine to notify IkeSessionStateMachine. */
    private class ChildSessionSmCallback
            implements ChildSessionStateMachine.IChildSessionSmCallback {
        @Override
        public void onChildSaCreated(int remoteSpi, ChildSessionStateMachine childSession) {
            mSpiToChildSessionMap.put(remoteSpi, childSession);
        }

        @Override
        public void onChildSaDeleted(int remoteSpi) {
            mSpiToChildSessionMap.remove(remoteSpi);
        }

        @Override
        public void onOutboundPayloadsReady(
                @ExchangeType int exchangeType, boolean isResp, List<IkePayload> payloadList) {
            sendMessage(
                    CMD_OUTBOUND_CHILD_PAYLOADS_READY,
                    exchangeType,
                    isResp ? CHILD_PAYLOADS_DIRECTION_RESPONSE : CHILD_PAYLOADS_DIRECTION_REQUEST,
                    payloadList);
        }

        @Override
        public void onProcedureFinished(ChildSessionStateMachine childSession) {
            sendMessage(CMD_CHILD_PROCEDURE_FINISHED, childSession);
        }

        @Override
        public void onFatalIkeSessionError(boolean needsNotifyRemote) {
            // TODO: If needsNotifyRemote is true, send a Delete IKE request and then kill the IKE
            // Session. Otherwise, directly kill the IKE Session.
        }
    }

    /** Initial state of IkeSessionStateMachine. */
    class Initial extends State {
        @Override
        public void enter() {
            try {
                mRemoteAddress = mIkeSessionOptions.getServerAddress();

                boolean isIpv4 = mRemoteAddress instanceof Inet4Address;
                FileDescriptor sock =
                        Os.socket(
                                isIpv4 ? OsConstants.AF_INET : OsConstants.AF_INET6,
                                OsConstants.SOCK_DGRAM,
                                OsConstants.IPPROTO_UDP);
                Os.connect(sock, mRemoteAddress, IkeSocket.IKE_SERVER_PORT);
                InetSocketAddress localAddr = (InetSocketAddress) Os.getsockname(sock);
                mLocalAddress = localAddr.getAddress();
                mLocalPort = localAddr.getPort();
                Os.close(sock);

                mIkeSocket = IkeSocket.getIkeSocket(mIkeSessionOptions.getUdpEncapsulationSocket());
            } catch (ErrnoException | SocketException e) {
                // TODO: handle exception and close IkeSession.
            }
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_LOCAL_REQUEST_CREATE_IKE:
                    transitionTo(mCreateIkeLocalIkeInit);
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
     * Closed represents the state when this IkeSessionStateMachine is closed, and no further
     * actions can be performed on it.
     */
    class Closed extends State {
        @Override
        public void enter() {
            // TODO: Notify all child sessions that they have been force-closed
            // TODO: Notify user that IKE Session is closed.
            // TODO: Cleanup all state
        }
    }

    /**
     * Idle represents a state when there is no ongoing IKE exchange affecting established IKE SA.
     */
    class Idle extends LocalRequestQueuer {
        @Override
        public void enter() {
            mScheduler.readyForNextProcedure();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_IKE_PACKET:
                    deferMessage(message);
                    transitionTo(mReceiving);
                    return HANDLED;

                case CMD_FORCE_TRANSITION: // Testing command
                    transitionTo((State) message.obj);
                    return HANDLED;

                case CMD_EXECUTE_LOCAL_REQ:
                    executeLocalRequest((LocalRequest) message.obj, message);
                    return HANDLED;

                default:
                    // Queue local requests, and trigger next procedure
                    if (message.what >= CMD_LOCAL_REQUEST_BASE
                            && message.what < CMD_LOCAL_REQUEST_BASE + CMD_CATEGORY_SIZE) {
                        handleLocalRequest(message.what);

                        // Synchronously calls through to the scheduler callback, which will
                        // post the CMD_EXECUTE_LOCAL_REQ to the front of the queue, ensuring
                        // it is always the next request processed.
                        mScheduler.readyForNextProcedure();
                        return HANDLED;
                    }
                    return NOT_HANDLED;
            }
        }

        private void executeLocalRequest(LocalRequest req, Message message) {
            switch (req.procedureType) {
                case CMD_LOCAL_REQUEST_REKEY_IKE:
                    transitionTo(mRekeyIkeLocalCreate);
                    break;
                case CMD_LOCAL_REQUEST_DELETE_IKE:
                    transitionTo(mDeleteIkeLocalDelete);
                    break;
                case CMD_LOCAL_REQUEST_CREATE_CHILD:
                    deferMessage(message);
                    transitionTo(mChildProcedureOngoing);
                    break;
                default:
                    Log.wtf(TAG, "Invalid local request procedure type: " + req.procedureType);
                    break;
            }
        }
    }

    /**
     * Gets IKE exchange subtype of a inbound IKE request message.
     *
     * <p>Knowing IKE exchange subtype of a inbound IKE request message helps IkeSessionStateMachine
     * to validate this request using the specific rule.
     *
     * <p>It is not allowed to obtain exchange subtype from a inbound response message for two
     * reasons. Firstly, the exchange subtype of a response message is the same with its
     * corresponding request message. Secondly, trying to get the exchange subtype from a response
     * message will easily fail when the response message contains only error notification payloads.
     *
     * @param ikeMessage inbound request IKE message to check.
     * @return IKE exchange subtype.
     */
    @IkeExchangeSubType
    private static int getIkeExchangeSubType(IkeMessage ikeMessage) {
        IkeHeader ikeHeader = ikeMessage.ikeHeader;
        if (ikeHeader.isResponseMsg) {
            // STOPSHIP: b/130190639 Notify user the error and close IKE session.
            throw new UnsupportedOperationException(
                    "Do not support getting IKE exchange subtype from a response message.");
        }

        switch (ikeHeader.exchangeType) {
                // DPD omitted - should never be handled via handleRequestIkeMessage()
            case IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT:
                return IKE_EXCHANGE_SUBTYPE_IKE_INIT;
            case IkeHeader.EXCHANGE_TYPE_IKE_AUTH:
                return IKE_EXCHANGE_SUBTYPE_IKE_AUTH;
            case IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA:
                // It is guaranteed in the decoding process that SA Payload has at least one SA
                // Proposal. Since Rekey IKE and Create Child (both initial creation and rekey
                // creation) will cause a collision, although the RFC 7296 does not prohibit one SA
                // Payload to contain both IKE proposals and Child proposals, containing two types
                // does not make sense. IKE libary will reply according to the first SA Proposal
                // type and ignore the other type.
                IkeSaPayload saPayload =
                        ikeMessage.getPayloadForType(
                                IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
                if (saPayload == null) {
                    return IKE_EXCHANGE_SUBTYPE_INVALID;
                }

                // If the received message has both SA(IKE) Payload and Notify-Rekey Payload, IKE
                // library will treat it as a Rekey IKE request and ignore the Notify-Rekey
                // Payload to provide better interoperability.
                if (saPayload.proposalList.get(0).protocolId == IkePayload.PROTOCOL_ID_IKE) {
                    return IKE_EXCHANGE_SUBTYPE_REKEY_IKE;
                }

                // If a Notify-Rekey Payload is found, this message is for rekeying a Child SA.
                List<IkeNotifyPayload> notifyPayloads =
                        ikeMessage.getPayloadListForType(
                                IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);

                // It is checked during decoding that there is at most one Rekey notification
                // payload.
                for (IkeNotifyPayload notifyPayload : notifyPayloads) {
                    if (notifyPayload.notifyType == IkeNotifyPayload.NOTIFY_TYPE_REKEY_SA) {
                        return IKE_EXCHANGE_SUBTYPE_REKEY_CHILD;
                    }
                }

                return IKE_EXCHANGE_SUBTYPE_CREATE_CHILD;
            case IkeHeader.EXCHANGE_TYPE_INFORMATIONAL:
                List<IkeDeletePayload> deletePayloads =
                        ikeMessage.getPayloadListForType(
                                IkePayload.PAYLOAD_TYPE_DELETE, IkeDeletePayload.class);

                // If no Delete payload was found, this request is a generic informational request.
                if (deletePayloads.isEmpty()) return IKE_EXCHANGE_SUBTYPE_GENERIC_INFO;

                // IKEv2 protocol does not clearly disallow to have both a Delete IKE payload and a
                // Delete Child payload in one IKE message. In this case, IKE library will only
                // respond to the Delete IKE payload.
                for (IkeDeletePayload deletePayload : deletePayloads) {
                    if (deletePayload.protocolId == IkePayload.PROTOCOL_ID_IKE) {
                        return IKE_EXCHANGE_SUBTYPE_DELETE_IKE;
                    }
                }
                return IKE_EXCHANGE_SUBTYPE_DELETE_CHILD;
            default:
                // STOPSHIP: b/130190639 Notify user the error and close IKE session.
                throw new IllegalArgumentException(
                        "Unrecognized exchange type: " + ikeHeader.exchangeType);
        }
    }

    // Sends the provided IkeMessage using the current IKE SA record
    @VisibleForTesting
    void sendEncryptedIkeMessage(IkeMessage msg) {
        sendEncryptedIkeMessage(mCurrentIkeSaRecord, msg);
    }

    // Sends the provided IkeMessage using the provided IKE SA record
    @VisibleForTesting
    void sendEncryptedIkeMessage(IkeSaRecord ikeSaRecord, IkeMessage msg) {
        byte[] bytes = msg.encryptAndEncode(mIkeIntegrity, mIkeCipher, ikeSaRecord);
        mIkeSocket.sendIkePacket(bytes, mRemoteAddress);
    }

    // Builds an Encrypted IKE Informational Message for the given IkeInformationalPayload using the
    // current IKE SA record.
    @VisibleForTesting
    IkeMessage buildEncryptedInformationalMessage(
            IkeInformationalPayload[] payloads, boolean isResponse, int messageId) {
        return buildEncryptedInformationalMessage(
                mCurrentIkeSaRecord, payloads, isResponse, messageId);
    }

    // Builds an Encrypted IKE Informational Message for the given IkeInformationalPayload using the
    // provided IKE SA record.
    @VisibleForTesting
    IkeMessage buildEncryptedInformationalMessage(
            IkeSaRecord saRecord,
            IkeInformationalPayload[] payloads,
            boolean isResponse,
            int messageId) {
        return buildEncryptedNotificationMessage(
                saRecord, payloads, IkeHeader.EXCHANGE_TYPE_INFORMATIONAL, isResponse, messageId);
    }

    // Builds an Encrypted IKE Message for the given IkeInformationalPayload using the provided IKE
    // SA record and exchange type.
    @VisibleForTesting
    IkeMessage buildEncryptedNotificationMessage(
            IkeSaRecord saRecord,
            IkeInformationalPayload[] payloads,
            @ExchangeType int exchangeType,
            boolean isResponse,
            int messageId) {
        IkeHeader header =
                new IkeHeader(
                        saRecord.getInitiatorSpi(),
                        saRecord.getResponderSpi(),
                        IkePayload.PAYLOAD_TYPE_SK,
                        exchangeType,
                        isResponse /*isResponseMsg*/,
                        saRecord.isLocalInit /*fromIkeInitiator*/,
                        messageId);

        return new IkeMessage(header, Arrays.asList(payloads));
    }

    private abstract class LocalRequestQueuer extends State {
        protected void handleLocalRequest(int requestVal) {
            switch (requestVal) {
                case CMD_LOCAL_REQUEST_DELETE_IKE:
                    mScheduler.addRequestAtFront(new LocalRequest(requestVal));
                    return;

                case CMD_LOCAL_REQUEST_REKEY_IKE: // Fallthrough
                case CMD_LOCAL_REQUEST_INFO: // Fallthrough
                case CMD_LOCAL_REQUEST_CREATE_CHILD: // Fallthrough
                case CMD_LOCAL_REQUEST_REKEY_CHILD: // Fallthrough
                case CMD_LOCAL_REQUEST_DELETE_CHILD:
                    mScheduler.addRequest(new LocalRequest(requestVal));
                    return;

                default:
                    logw("Unknown local request passed to handleLocalRequest");
            }
        }
    }

    /** Base state defines common behaviours when receiving an IKE packet. */
    private abstract class BusyState extends LocalRequestQueuer {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_IKE_PACKET:
                    handleReceivedIkePacket(message);
                    return HANDLED;

                case CMD_FORCE_TRANSITION:
                    transitionTo((State) message.obj);
                    return HANDLED;

                case CMD_EXECUTE_LOCAL_REQ:
                    Log.wtf(TAG, "Invalid execute local request command in non-idle state");
                    return NOT_HANDLED;

                default:
                    // Queue local requests, and trigger next procedure
                    if (message.what >= CMD_LOCAL_REQUEST_BASE
                            && message.what < CMD_LOCAL_REQUEST_BASE + CMD_CATEGORY_SIZE) {
                        handleLocalRequest(message.what);
                        return HANDLED;
                    }
                    return NOT_HANDLED;
            }
        }

        protected IkeSaRecord getIkeSaRecordForPacket(IkeHeader ikeHeader) {
            if (ikeHeader.fromIkeInitiator) {
                return mSpiToSaRecordMap.get(ikeHeader.ikeInitiatorSpi);
            } else {
                return mSpiToSaRecordMap.get(ikeHeader.ikeResponderSpi);
            }
        }

        protected void handleReceivedIkePacket(Message message) {
            ReceivedIkePacket receivedIkePacket = (ReceivedIkePacket) message.obj;
            IkeHeader ikeHeader = receivedIkePacket.ikeHeader;
            byte[] ikePacketBytes = receivedIkePacket.ikePacketBytes;
            IkeSaRecord ikeSaRecord = getIkeSaRecordForPacket(ikeHeader);

            // Drop packets that we don't have an SA for:
            if (ikeSaRecord == null) {
                // TODO: Print a summary of the IKE message (perhaps the IKE header)
                Log.v(TAG, "No matching SA for packet");
                return;
            }

            if (ikeHeader.isResponseMsg) {
                DecodeResult decodeResult =
                        IkeMessage.decode(
                                ikeSaRecord.getLocalRequestMessageId(),
                                mIkeIntegrity,
                                mIkeCipher,
                                ikeSaRecord,
                                ikeHeader,
                                ikePacketBytes);
                switch (decodeResult.status) {
                    case DECODE_STATUS_OK:
                        ikeSaRecord.incrementLocalRequestMessageId();
                        handleResponseIkeMessage(decodeResult.ikeMessage);
                        break;
                    case DECODE_STATUS_PROTECTED_ERROR_MESSAGE:
                        ikeSaRecord.incrementLocalRequestMessageId();
                        // TODO: Send Delete request on all IKE SAs and close IKE Session.
                        throw new UnsupportedOperationException("Cannot handle this error.");
                    case DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE:
                        // TODO: Log and ignore this message
                        throw new UnsupportedOperationException("Cannot handle this error.");
                    default:
                        throw new IllegalArgumentException("Unrecognized decoding status.");
                }

            } else {
                int expectedMsgId = ikeSaRecord.getRemoteRequestMessageId();
                if (expectedMsgId - ikeHeader.messageId == 1) {
                    // TODO: Handle retransmitted request.
                    throw new UnsupportedOperationException(
                            "Do not support handling retransmitted request.");
                } else {
                    DecodeResult decodeResult =
                            IkeMessage.decode(
                                    expectedMsgId,
                                    mIkeIntegrity,
                                    mIkeCipher,
                                    ikeSaRecord,
                                    ikeHeader,
                                    ikePacketBytes);
                    switch (decodeResult.status) {
                        case DECODE_STATUS_OK:
                            ikeSaRecord.incrementRemoteRequestMessageId();
                            IkeMessage ikeMessage = decodeResult.ikeMessage;

                            // Handle DPD here.
                            if (ikeMessage.isDpdRequest()) {
                                IkeMessage dpdResponse =
                                        buildEncryptedInformationalMessage(
                                                ikeSaRecord,
                                                new IkeInformationalPayload[] {},
                                                true,
                                                ikeHeader.messageId);
                                sendEncryptedIkeMessage(ikeSaRecord, dpdResponse);

                                // Notify state if it is listening for DPD packets
                                handleDpd();
                                break;
                            }

                            int ikeExchangeSubType = getIkeExchangeSubType(ikeMessage);
                            if (ikeExchangeSubType == IKE_EXCHANGE_SUBTYPE_INVALID) {
                                // TODO: Reply with INVALID_SYNTAX and close IKE Session.
                                throw new UnsupportedOperationException(
                                        "Cannot handle message with invalid IkeExchangeSubType.");
                            }
                            handleRequestIkeMessage(ikeMessage, ikeExchangeSubType, message);
                            break;
                        case DECODE_STATUS_PROTECTED_ERROR_MESSAGE:
                            ikeSaRecord.incrementRemoteRequestMessageId();
                            // TODO: Send back error notification. Close IKE Session if this is
                            // INVALID_SYNTAX error.
                            break;
                        case DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE:
                            // TODO: Log and ignore this message.
                            break;
                        default:
                            throw new IllegalArgumentException("Unrecognized decoding status.");
                    }
                }
            }

            // TODO: Handle fatal error notifications.
        }

        protected void handleDpd() {
            // Do nothing - Child states should override if they care.
        }

        // Default handler for decode errors in encrypted request.
        protected void handleDecodingErrorInEncryptedRequest(
                IkeProtocolException exception, IkeSaRecord ikeSaRecord) {
            switch (exception.getErrorType()) {
                case ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD:
                    // TODO: Send encrypted error notification.
                    return;
                case ERROR_TYPE_INVALID_MAJOR_VERSION:
                    // TODO: Send unencrypted error notification.
                    return;
                case ERROR_TYPE_INVALID_SYNTAX:
                    // TODO: Send encrypted error notification and close IKE session if Message ID
                    // and cryptogtaphic checksum were invalid.
                    return;
                default:
                    Log.wtf(TAG, "Unknown error decoding IKE Message.");
            }
        }

        // Default handler for decode errors in encrypted responses.
        // NOTE: The DeleteIkeLocal state MUST override this state to avoid the possibility of an
        // infinite loop.
        protected void handleDecodingErrorInEncryptedResponse(
                IkeProtocolException exception, IkeSaRecord ikeSaRecord) {
            // All errors in parsing or processing reponse packets should cause the IKE library to
            // initiate a Delete IKE Exchange.

            // TODO: Initiate Delete IKE Exchange
        }

        protected abstract void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message);

        protected abstract void handleResponseIkeMessage(IkeMessage ikeMessage);
    }

    /**
     * Retransmitter represents a RAII class to send the initial request, and retransmit as needed.
     *
     * <p>The Retransmitter class will automatically start transmission upon creation.
     */
    @VisibleForTesting
    class Retransmitter {
        private final IkeMessage mRetransmitMsg;
        private final IkeSaRecord mIkeSaRecord;

        @VisibleForTesting
        Retransmitter(IkeMessage msg) {
            this(mCurrentIkeSaRecord, msg);
        }

        @VisibleForTesting
        Retransmitter(IkeSaRecord ikeSaRecord, IkeMessage msg) {
            mIkeSaRecord = ikeSaRecord;
            mRetransmitMsg = msg;

            sendAndStartRetransmission();
        }

        private void sendAndStartRetransmission() {
            if (mRetransmitMsg == null) {
                return;
            }

            send(mRetransmitMsg);
        }

        protected void send(IkeMessage msg) {
            sendEncryptedIkeMessage(mIkeSaRecord, mRetransmitMsg);
        }

        public void stopRetransmitting() {}

        public IkeMessage getMessage() {
            return mRetransmitMsg;
        }
    }

    /**
     * DeleteResponderBase represents all states after IKE_INIT and IKE_AUTH.
     *
     * <p>All post-init states share common functionality of being able to respond to IKE_DELETE
     * requests.
     */
    private abstract class DeleteResponderBase extends BusyState {
        /** Builds a IKE Delete Response for the given IKE SA and request. */
        protected IkeMessage buildIkeDeleteResp(IkeMessage req, IkeSaRecord ikeSaRecord) {
            IkeInformationalPayload[] payloads = new IkeInformationalPayload[] {};
            return buildEncryptedInformationalMessage(
                    ikeSaRecord, payloads, true /* isResp */, req.ikeHeader.messageId);
        }

        /**
         * Validates that the delete request is acceptable.
         *
         * <p>The request message must be guaranteed by previous checks to be of SUBTYPE_DELETE_IKE,
         * and therefore contains an IkeDeletePayload. This is checked in getIkeExchangeSubType.
         */
        protected void validateIkeDeleteReq(IkeMessage req, IkeSaRecord expectedRecord)
                throws InvalidSyntaxException {
            if (expectedRecord != getIkeSaRecordForPacket(req.ikeHeader)) {
                throw new InvalidSyntaxException("Unexpected delete request for SA");
            }
        }

        /**
         * Helper method for responding to a session deletion request
         *
         * <p>Note that this method expects that the session is keyed on the current IKE SA session,
         * and closing the IKE SA indicates that the remote wishes to end the session as a whole. As
         * such, this should not be used in rekey cases where there is any ambiguity as to which IKE
         * SA the session is reliant upon.
         *
         * <p>Note that this method will also move the state machine to the closed state.
         *
         * @param ikeMessage The received session deletion request
         */
        protected void handleDeleteSessionRequest(IkeMessage ikeMessage) {
            try {
                validateIkeDeleteReq(ikeMessage, mCurrentIkeSaRecord);
                IkeMessage resp = buildIkeDeleteResp(ikeMessage, mCurrentIkeSaRecord);
                sendEncryptedIkeMessage(mCurrentIkeSaRecord, resp);

                removeIkeSaRecord(mCurrentIkeSaRecord);
                mCurrentIkeSaRecord.close();
                mCurrentIkeSaRecord = null;

                transitionTo(mClosed);
            } catch (InvalidSyntaxException e) {
                Log.wtf(TAG, "Got deletion of a non-Current IKE SA - rekey error?", e);
                // TODO: Send the INVALID_SYNTAX error
            }
        }
    }

    /**
     * DeleteBase abstracts deletion handling for all states initiating a delete exchange
     *
     * <p>All subclasses of this state share common functionality that a deletion request is sent,
     * and the response is received.
     */
    private abstract class DeleteBase extends DeleteResponderBase {
        /** Builds a IKE Delete Request for the given IKE SA. */
        protected IkeMessage buildIkeDeleteReq(IkeSaRecord ikeSaRecord) {
            IkeInformationalPayload[] payloads =
                    new IkeInformationalPayload[] {new IkeDeletePayload()};
            return buildEncryptedInformationalMessage(
                    ikeSaRecord,
                    payloads,
                    false /* isResp */,
                    ikeSaRecord.getLocalRequestMessageId());
        }

        protected void validateIkeDeleteResp(IkeMessage resp, IkeSaRecord expectedSaRecord)
                throws InvalidSyntaxException {
            if (expectedSaRecord != getIkeSaRecordForPacket(resp.ikeHeader)) {
                throw new InvalidSyntaxException("Response received on incorrect SA");
            }

            if (resp.ikeHeader.exchangeType != IkeHeader.EXCHANGE_TYPE_INFORMATIONAL) {
                throw new InvalidSyntaxException(
                        "Invalid exchange type; expected INFORMATIONAL, but got: "
                                + resp.ikeHeader.exchangeType);
            }

            if (!resp.ikePayloadList.isEmpty()) {
                throw new InvalidSyntaxException(
                        "Unexpected payloads - IKE Delete response should be empty.");
            }
        }
    }

    /**
     * Receiving represents a state when idle IkeSessionStateMachine receives an incoming packet.
     */
    class Receiving extends RekeyIkeHandlerBase {
        @Override
        protected void handleDpd() {
            // Go back to IDLE - the received request was a DPD
            transitionTo(mIdle);
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_REKEY_IKE:
                    try {
                        validateIkeRekeyReq(ikeMessage);

                        // TODO: Add support for limited re-negotiation of parameters

                        // Build a rekey response payload with our previously selected proposal,
                        // against which we will validate the received proposals.
                        IkeSaPayload reqSaPayload =
                                ikeMessage.getPayloadForType(
                                        IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
                        byte respProposalNumber =
                                reqSaPayload.getNegotiatedProposalNumber(mSaProposal);

                        List<IkePayload> payloadList =
                                CreateIkeSaHelper.getRekeyIkeSaResponsePayloads(
                                        respProposalNumber, mSaProposal, mLocalAddress);

                        // Build IKE header
                        IkeHeader ikeHeader =
                                new IkeHeader(
                                        mCurrentIkeSaRecord.getInitiatorSpi(),
                                        mCurrentIkeSaRecord.getResponderSpi(),
                                        IkePayload.PAYLOAD_TYPE_SK,
                                        IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                                        true /*isResponseMsg*/,
                                        mCurrentIkeSaRecord.isLocalInit,
                                        ikeMessage.ikeHeader.messageId);

                        IkeMessage responseIkeMessage = new IkeMessage(ikeHeader, payloadList);

                        // Build new SA first to ensure that we can find a valid proposal.
                        mRemoteInitNewIkeSaRecord =
                                validateAndBuildIkeSa(
                                        ikeMessage, responseIkeMessage, false /*isLocalInit*/);

                        sendEncryptedIkeMessage(responseIkeMessage);
                        transitionTo(mRekeyIkeRemoteDelete);
                    } catch (IkeProtocolException e) {
                        // TODO: Handle processing errors.
                        Log.e(TAG, "IkeProtocolException: ", e);
                    } catch (GeneralSecurityException e) {
                        // TODO: Fatal - kill session.
                        Log.e(TAG, "GeneralSecurityException: ", e);
                    } catch (IOException e) {
                        // TODO: SPI allocation collided - they reused an SPI. Terminate session.
                        Log.e(TAG, "IOException: ", e);
                    }
                    return;
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    handleDeleteSessionRequest(ikeMessage);
                    return;
                default:
                    // TODO: Add more cases for supporting other types of request.
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            // TODO: Extract payloads and re-direct to awaiting ChildSessionStateMachines.
        }
    }

    /**
     * This class represents a state when there is at least one ongoing Child procedure
     * (Create/Rekey/Delete Child)
     */
    class ChildProcedureOngoing extends DeleteBase {
        // It is possible that mChildInLocalProcedure and mChildInRemoteProcedure are the same
        // when both sides initiated exchange for the same Child Session.
        private ChildSessionStateMachine mChildInLocalProcedure;
        private ChildSessionStateMachine mChildInRemoteProcedure;

        private int mLastInboundRequestMsgId;

        // TODO: Support retransmitting.

        // TODO: Store multiple mChildInRemoteProcedures to support multiple Child SAs deletion
        // initiated by the remote.

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_REQUEST_FOR_CHILD:
                    handleRequestIkeMessage(
                            (IkeMessage) message.obj,
                            message.arg1 /*ikeExchangeSubType*/,
                            null /*ReceivedIkePacket*/);
                    return HANDLED;
                case CMD_OUTBOUND_CHILD_PAYLOADS_READY:
                    int exchangeType = message.arg1;
                    boolean isResp = (message.arg2 == CHILD_PAYLOADS_DIRECTION_RESPONSE);

                    if (isResp) {
                        handleOutboundResponse(exchangeType, (List<IkePayload>) message.obj);
                    } else {
                        handleOutboundRequest(exchangeType, (List<IkePayload>) message.obj);
                    }

                    return HANDLED;
                case CMD_CHILD_PROCEDURE_FINISHED:
                    ChildSessionStateMachine childSession = (ChildSessionStateMachine) message.obj;

                    if (mChildInLocalProcedure == childSession) {
                        mChildInLocalProcedure = null;
                    }
                    if (mChildInRemoteProcedure == childSession) {
                        mChildInRemoteProcedure = null;
                    }

                    if (mChildInLocalProcedure == null && mChildInRemoteProcedure == null) {
                        transitionTo(mIdle);
                    }
                    return HANDLED;
                case CMD_HANDLE_FIRST_CHILD_NEGOTIATION:
                    FirstChildNegotiationData childData = (FirstChildNegotiationData) message.obj;

                    mChildInLocalProcedure = buildChildSession(childData.childSessionOptions);
                    mChildInLocalProcedure.handleFirstChildExchange(
                            childData.reqPayloads, childData.respPayloads);
                    return HANDLED;
                case CMD_EXECUTE_LOCAL_REQ:
                    executeLocalRequest((ChildLocalRequest) message.obj);
                    return HANDLED;
                default:
                    return super.processMessage(message);
            }
        }

        private ChildSessionStateMachine buildChildSession(ChildSessionOptions childOptions) {
            boolean isNatDetected = mIsLocalBehindNat || mIsRemoteBehindNat;

            // TODO: Also pass IChildSessionCallback to ChildSessionStateMachine.
            ChildSessionStateMachine childSession =
                    ChildSessionStateMachineFactory.makeChildSessionStateMachine(
                            getHandler().getLooper(),
                            mContext,
                            childOptions,
                            new ChildSessionSmCallback(),
                            mLocalAddress,
                            mRemoteAddress,
                            (isNatDetected ? mIkeSessionOptions.getUdpEncapsulationSocket() : null),
                            mIkePrf,
                            mCurrentIkeSaRecord.getSkD());
            return childSession;
        }

        private void executeLocalRequest(ChildLocalRequest req) {
            switch (req.procedureType) {
                    // TODO: Also support Delete Child and Rekey Child.
                case CMD_LOCAL_REQUEST_CREATE_CHILD:
                    mChildInLocalProcedure = buildChildSession(req.childSessionOptions);
                    mChildInLocalProcedure.createChildSession();
                    break;
                default:
                    Log.wtf(TAG, "Invalid Child procedure type: " + req.procedureType);
                    if (mChildInRemoteProcedure == null) {
                        transitionTo(mIdle);
                    }
                    break;
            }
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            // TODO: Grab a remote lock and hand payloads to the Child Session
            mLastInboundRequestMsgId = ikeMessage.ikeHeader.messageId;
            throw new UnsupportedOperationException("Cannot handle inbound Child request");
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            // TODO: Stop retransimitting

            List<IkePayload> handledPayloads = new LinkedList<>();

            for (IkePayload payload : ikeMessage.ikePayloadList) {
                switch (payload.payloadType) {
                    case PAYLOAD_TYPE_NOTIFY:
                        // TODO: Handle fatal IKE error notification and IKE status notification.
                        break;
                    case PAYLOAD_TYPE_VENDOR:
                        // TODO: Handle Vendor ID Payload
                        handledPayloads.add(payload);
                        break;
                    case PAYLOAD_TYPE_CP:
                        // TODO: Handle IKE related configuration attributes and pass the payload to
                        // Child to further handle internal IP address attributes.
                        break;
                    default:
                        break;
                }
            }

            List<IkePayload> payloads = new LinkedList<>();
            payloads.addAll(ikeMessage.ikePayloadList);
            payloads.removeAll(handledPayloads);

            mChildInLocalProcedure.receiveResponse(ikeMessage.ikeHeader.exchangeType, payloads);
        }

        private void handleOutboundRequest(int exchangeType, List<IkePayload> outboundPayloads) {
            IkeHeader ikeHeader =
                    new IkeHeader(
                            mCurrentIkeSaRecord.getInitiatorSpi(),
                            mCurrentIkeSaRecord.getResponderSpi(),
                            IkePayload.PAYLOAD_TYPE_SK,
                            exchangeType,
                            false /*isResp*/,
                            mCurrentIkeSaRecord.isLocalInit,
                            mCurrentIkeSaRecord.getLocalRequestMessageId());
            IkeMessage ikeMessage = new IkeMessage(ikeHeader, outboundPayloads);

            sendEncryptedIkeMessage(ikeMessage);
            // TODO: Start retransmission
        }

        private void handleOutboundResponse(int exchangeType, List<IkePayload> outboundPayloads) {
            // TODO: Build and send out response when all Child Sessions have replied.
        }
    }

    /** CreateIkeLocalIkeInit represents state when IKE library initiates IKE_INIT exchange. */
    class CreateIkeLocalIkeInit extends BusyState {
        private IkeSecurityParameterIndex mLocalIkeSpiResource;
        private IkeSecurityParameterIndex mRemoteIkeSpiResource;
        private Retransmitter mRetransmitter;

        @Override
        public void enter() {
            IkeMessage request = buildRequest();
            mIkeSocket.registerIke(request.ikeHeader.ikeInitiatorSpi, IkeSessionStateMachine.this);

            mIkeInitRequestBytes = request.encode();
            mIkeInitNoncePayload =
                    request.getPayloadForType(IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class);
            mRetransmitter = new UnencryptedRetransmitter(request);
        }

        private IkeMessage buildRequest() {
            try {
                return buildIkeInitReq();
            } catch (IOException e) {
                // TODO: Handle SPI assigning failure.
                throw new UnsupportedOperationException(
                        "Do not support handling SPI assigning failure.");
            }
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_IKE_PACKET:
                    handleReceivedIkePacket(message);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        protected void handleReceivedIkePacket(Message message) {
            ReceivedIkePacket receivedIkePacket = (ReceivedIkePacket) message.obj;
            IkeHeader ikeHeader = receivedIkePacket.ikeHeader;
            byte[] ikePacketBytes = receivedIkePacket.ikePacketBytes;
            if (ikeHeader.isResponseMsg) {
                DecodeResult decodeResult = IkeMessage.decode(0, ikeHeader, ikePacketBytes);

                switch (decodeResult.status) {
                    case DECODE_STATUS_OK:
                        handleResponseIkeMessage(decodeResult.ikeMessage);
                        mIkeInitResponseBytes = ikePacketBytes;
                        mCurrentIkeSaRecord.incrementLocalRequestMessageId();
                        break;
                    case DECODE_STATUS_PROTECTED_ERROR_MESSAGE:
                        // Fall through to default
                    case DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE:
                        // TODO:Since IKE_INIT is not protected, log and ignore this message.
                        throw new UnsupportedOperationException("Cannot handle this error.");
                    default:
                        throw new IllegalArgumentException(
                                "Invalid decoding status: " + decodeResult.status);
                }

            } else {
                // TODO: Also prettyprint IKE header in the log.
                Log.e(TAG, "Received a request while waiting for IKE_INIT response.");
            }
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            Log.wtf(
                    TAG,
                    "State: "
                            + getCurrentState().getName()
                            + " received an unsupported request message with IKE exchange subtype: "
                            + ikeExchangeSubType);
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            boolean ikeInitSuccess = false;
            try {
                validateIkeInitResp(mRetransmitter.getMessage(), ikeMessage);

                // TODO: Pass mLocalIkeSpiResource and mRemoteIkeSpiResource to
                // makeFirstIkeSaRecord()
                mCurrentIkeSaRecord =
                        IkeSaRecord.makeFirstIkeSaRecord(
                                mRetransmitter.getMessage(),
                                ikeMessage,
                                mLocalIkeSpiResource,
                                mRemoteIkeSpiResource,
                                mIkePrf,
                                mIkeIntegrity == null ? 0 : mIkeIntegrity.getKeyLength(),
                                mIkeCipher.getKeyLength());
                addIkeSaRecord(mCurrentIkeSaRecord);
                ikeInitSuccess = true;

                transitionTo(mCreateIkeLocalIkeAuth);
            } catch (IkeProtocolException e) {
                // TODO: Handle processing errors.
            } catch (GeneralSecurityException e) {
                // TODO: Handle DH key exchange failure.
            } catch (IOException e) {
                // TODO: Handle the error case when the remote IKE SPI has been reserved with the
                // remote address.
            } finally {
                if (!ikeInitSuccess) {
                    if (mLocalIkeSpiResource != null) {
                        mLocalIkeSpiResource.close();
                        mLocalIkeSpiResource = null;
                    }
                    if (mRemoteIkeSpiResource != null) {
                        mRemoteIkeSpiResource.close();
                        mRemoteIkeSpiResource = null;
                    }
                }
            }
        }

        private IkeMessage buildIkeInitReq() throws IOException {
            // Generate IKE SPI
            mLocalIkeSpiResource =
                    IkeSecurityParameterIndex.allocateSecurityParameterIndex(mLocalAddress);
            long initSpi = mLocalIkeSpiResource.getSpi();
            long respSpi = 0;

            // It is validated in IkeSessionOptions.Builder to ensure IkeSessionOptions has at least
            // one SaProposal and all SaProposals are valid for IKE SA negotiation.
            SaProposal[] saProposals = mIkeSessionOptions.getSaProposals();
            List<IkePayload> payloadList =
                    CreateIkeSaHelper.getIkeInitSaRequestPayloads(
                            saProposals,
                            initSpi,
                            respSpi,
                            mLocalAddress,
                            mRemoteAddress,
                            mLocalPort,
                            IkeSocket.IKE_SERVER_PORT);

            // TODO: Add Notification Payloads according to user configurations.

            // Build IKE header
            IkeHeader ikeHeader =
                    new IkeHeader(
                            initSpi,
                            respSpi,
                            IkePayload.PAYLOAD_TYPE_SA,
                            IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT,
                            false /*isResponseMsg*/,
                            true /*fromIkeInitiator*/,
                            0 /*messageId*/);

            return new IkeMessage(ikeHeader, payloadList);
        }

        private void validateIkeInitResp(IkeMessage reqMsg, IkeMessage respMsg)
                throws IkeProtocolException, IOException {
            IkeHeader respIkeHeader = respMsg.ikeHeader;
            mRemoteIkeSpiResource =
                    IkeSecurityParameterIndex.allocateSecurityParameterIndex(
                            mIkeSessionOptions.getServerAddress(), respIkeHeader.ikeResponderSpi);

            int exchangeType = respIkeHeader.exchangeType;
            if (exchangeType != IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT) {
                throw new InvalidSyntaxException(
                        "Expected EXCHANGE_TYPE_IKE_SA_INIT but received: " + exchangeType);
            }

            IkeSaPayload respSaPayload = null;
            IkeKePayload respKePayload = null;

            /**
             * There MAY be multiple NAT_DETECTION_SOURCE_IP payloads in a message if the sender
             * does not know which of several network attachments will be used to send the packet.
             */
            List<IkeNotifyPayload> natSourcePayloads = new LinkedList<>();
            IkeNotifyPayload natDestPayload = null;

            boolean hasNoncePayload = false;

            for (IkePayload payload : respMsg.ikePayloadList) {
                switch (payload.payloadType) {
                    case IkePayload.PAYLOAD_TYPE_SA:
                        respSaPayload = (IkeSaPayload) payload;
                        break;
                    case IkePayload.PAYLOAD_TYPE_KE:
                        respKePayload = (IkeKePayload) payload;
                        break;
                    case IkePayload.PAYLOAD_TYPE_CERT_REQUEST:
                        throw new UnsupportedOperationException(
                                "Do not support handling Cert Request Payload.");
                        // TODO: Handle it when using certificate based authentication. Otherwise,
                        // ignore it.
                    case IkePayload.PAYLOAD_TYPE_NONCE:
                        hasNoncePayload = true;
                        mIkeRespNoncePayload = (IkeNoncePayload) payload;
                        break;
                    case IkePayload.PAYLOAD_TYPE_VENDOR:
                        // Do not support any vendor defined protocol extensions. Ignore
                        // all Vendor ID Payloads.
                        break;
                    case IkePayload.PAYLOAD_TYPE_NOTIFY:
                        IkeNotifyPayload notifyPayload = (IkeNotifyPayload) payload;
                        if (notifyPayload.isErrorNotify()) {
                            // TODO: Throw IkeExceptions according to error types.
                            throw new UnsupportedOperationException(
                                    "Do not support handle error notifications in response.");
                        }
                        switch (notifyPayload.notifyType) {
                            case NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP:
                                natSourcePayloads.add(notifyPayload);
                                break;
                            case NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP:
                                if (natDestPayload != null) {
                                    throw new InvalidSyntaxException(
                                            "More than one"
                                                    + " NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP"
                                                    + " found");
                                }
                                natDestPayload = notifyPayload;
                                break;
                            default:
                                // Unknown and unexpected status notifications are ignored as per
                                // RFC7296.
                                logw(
                                        "Received unknown or unexpected status notifications with"
                                                + " notify type: "
                                                + notifyPayload.notifyType);
                        }

                        break;
                    default:
                        throw new InvalidSyntaxException(
                                "Received unexpected payload in IKE INIT response. Payload type: "
                                        + payload.payloadType);
                }
            }

            if (respSaPayload == null
                    || respKePayload == null
                    || natSourcePayloads.isEmpty()
                    || natDestPayload == null
                    || !hasNoncePayload) {
                throw new InvalidSyntaxException(
                        "SA, KE, Nonce, Notify-NAT-Detection-Source, or"
                                + " Notify-NAT-Detection-Destination payload missing.");
            }

            IkeSaPayload reqSaPayload =
                    reqMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
            mSaProposal =
                    IkeSaPayload.getVerifiedNegotiatedIkeProposalPair(
                                    reqSaPayload, respSaPayload, mRemoteAddress)
                            .second
                            .saProposal;

            // Build IKE crypto tools using mSaProposal. It is ensured that mSaProposal is valid and
            // has exactly one Transform for each Transform type. Only exception is when
            // combined-mode cipher is used, there will be either no integrity algorithm or an
            // INTEGRITY_ALGORITHM_NONE type algorithm.
            Provider provider = IkeMessage.getSecurityProvider();
            mIkeCipher = IkeCipher.create(mSaProposal.getEncryptionTransforms()[0], provider);
            if (!mIkeCipher.isAead()) {
                mIkeIntegrity =
                        IkeMacIntegrity.create(mSaProposal.getIntegrityTransforms()[0], provider);
            }
            mIkePrf = IkeMacPrf.create(mSaProposal.getPrfTransforms()[0], provider);

            IkeKePayload reqKePayload =
                    reqMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);
            if (reqKePayload.dhGroup != respKePayload.dhGroup
                    && respKePayload.dhGroup != mSaProposal.getDhGroupTransforms()[0].id) {
                throw new InvalidSyntaxException("Received KE payload with mismatched DH group.");
            }

            // NAT detection
            long initIkeSpi = respMsg.ikeHeader.ikeInitiatorSpi;
            long respIkeSpi = respMsg.ikeHeader.ikeResponderSpi;
            mIsLocalBehindNat = true;
            mIsRemoteBehindNat = true;

            // Check if local node is behind NAT
            byte[] expectedLocalNatData =
                    IkeNotifyPayload.generateNatDetectionData(
                            initIkeSpi, respIkeSpi, mLocalAddress, mLocalPort);
            mIsLocalBehindNat = !Arrays.equals(expectedLocalNatData, natDestPayload.notifyData);

            // Check if the remote node is behind NAT
            byte[] expectedRemoteNatData =
                    IkeNotifyPayload.generateNatDetectionData(
                            initIkeSpi, respIkeSpi, mRemoteAddress, IkeSocket.IKE_SERVER_PORT);
            for (IkeNotifyPayload natPayload : natSourcePayloads) {
                // If none of the received hash matches the expected value, the remote node is
                // behind NAT.
                if (Arrays.equals(expectedRemoteNatData, natPayload.notifyData)) {
                    mIsRemoteBehindNat = false;
                }
            }
        }

        @Override
        public void exit() {
            super.exit();
            mRetransmitter.stopRetransmitting();
            // TODO: Store IKE_INIT request and response in mIkeSessionOptions for IKE_AUTH
        }

        private class UnencryptedRetransmitter extends Retransmitter {
            UnencryptedRetransmitter(IkeMessage msg) {
                super(null /* SaRecord */, msg);
            }

            @Override
            protected void send(IkeMessage msg) {
                // Sends unencrypted
                mIkeSocket.sendIkePacket(msg.encode(), mRemoteAddress);
            }
        }
    }

    /**
     * CreateIkeLocalIkeAuth represents state when IKE library initiates IKE_AUTH exchange.
     *
     * <p>If using EAP, CreateIkeLocalIkeAuth will transition to CreateIkeLocalIkeAuthInEap state
     * after validating the IKE AUTH response.
     */
    class CreateIkeLocalIkeAuth extends BusyState {
        private ChildSessionOptions mFirstChildSessionOptions;

        private Retransmitter mRetransmitter;
        private boolean mUseEap;

        /** This method set parameters for negotiating first Child SA during IKE AUTH exchange. */
        @VisibleForTesting
        void initializeAuthParams(ChildSessionOptions childOptions) {
            mFirstChildSessionOptions = childOptions;
            // TODO: Also assign mFirstChildCallback
        }

        @Override
        public void enter() {
            super.enter();
            mRetransmitter = new Retransmitter(buildRequest());
            mUseEap =
                    (IkeSessionOptions.IKE_AUTH_METHOD_EAP
                            == mIkeSessionOptions.getLocalAuthConfig().mAuthMethod);
        }

        private IkeMessage buildRequest() {
            try {
                return buildIkeAuthReq();
            } catch (ResourceUnavailableException e) {
                // TODO:Handle IPsec SPI assigning failure.
                throw new UnsupportedOperationException(
                        "Do not support handling IPsec SPI assigning failure.");
            }
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            Log.wtf(
                    TAG,
                    "State: "
                            + getCurrentState().getName()
                            + "received an unsupported request message with IKE exchange subtype: "
                            + ikeExchangeSubType);
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                int exchangeType = ikeMessage.ikeHeader.exchangeType;
                if (exchangeType != IkeHeader.EXCHANGE_TYPE_IKE_AUTH) {
                    throw new InvalidSyntaxException(
                            "Expected EXCHANGE_TYPE_IKE_AUTH but received: " + exchangeType);
                }

                if (mUseEap) {
                    // TODO: Implement #validateIkeAuthRespWithEapPayload() to validate Auth payload
                    // and extract EAP payload in the inbound message.
                    throw new UnsupportedOperationException("Do not support EAP.");
                } else {
                    validateIkeAuthRespWithChildPayloads(ikeMessage);

                    List<IkePayload> childReqList =
                            extractChildPayloadsFromMessage(mRetransmitter.getMessage());
                    List<IkePayload> childRespList = extractChildPayloadsFromMessage(ikeMessage);
                    childReqList.add(mIkeInitNoncePayload);
                    childRespList.add(mIkeRespNoncePayload);

                    deferMessage(
                            obtainMessage(
                                    CMD_HANDLE_FIRST_CHILD_NEGOTIATION,
                                    new FirstChildNegotiationData(
                                            mFirstChildSessionOptions,
                                            childReqList,
                                            childRespList)));

                    transitionTo(mChildProcedureOngoing);
                }
            } catch (IkeProtocolException e) {
                // TODO: Handle processing errors.
                throw new UnsupportedOperationException("Do not support handling error.", e);
            }
        }

        private IkeMessage buildIkeAuthReq() throws ResourceUnavailableException {
            List<IkePayload> payloadList = new LinkedList<>();

            // Build Identification payloads
            IkeIdPayload initIdPayload =
                    new IkeIdPayload(
                            true /*isInitiator*/, mIkeSessionOptions.getLocalIdentification());
            IkeIdPayload respIdPayload =
                    new IkeIdPayload(
                            false /*isInitiator*/, mIkeSessionOptions.getRemoteIdentification());
            payloadList.add(initIdPayload);
            payloadList.add(respIdPayload);

            // Build Authentication payload
            IkeAuthConfig authConfig = mIkeSessionOptions.getLocalAuthConfig();
            switch (authConfig.mAuthMethod) {
                case IkeSessionOptions.IKE_AUTH_METHOD_PSK:
                    IkeAuthPskPayload pskPayload =
                            new IkeAuthPskPayload(
                                    authConfig.mPsk,
                                    mIkeInitRequestBytes,
                                    mCurrentIkeSaRecord.nonceResponder,
                                    initIdPayload.getEncodedPayloadBody(),
                                    mIkePrf,
                                    mCurrentIkeSaRecord.getSkPi());
                    payloadList.add(pskPayload);
                    break;
                case IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE:
                    // TODO: Support authentication based on public key signature.
                    throw new UnsupportedOperationException(
                            "Do not support public-key based authentication.");
                case IkeSessionOptions.IKE_AUTH_METHOD_EAP:
                    // TODO: Support EAP.
                    throw new UnsupportedOperationException("Do not support EAP.");
                default:
                    throw new IllegalArgumentException(
                            "Unrecognized authentication method: " + authConfig.mAuthMethod);
            }

            payloadList.addAll(
                    CreateChildSaHelper.getInitCreateSaRequestPayloads(
                            mIpSecManager,
                            mLocalAddress,
                            mFirstChildSessionOptions,
                            true /*isFirstChild*/));

            // Build IKE header
            IkeHeader ikeHeader =
                    new IkeHeader(
                            mCurrentIkeSaRecord.getInitiatorSpi(),
                            mCurrentIkeSaRecord.getResponderSpi(),
                            IkePayload.PAYLOAD_TYPE_SK,
                            IkeHeader.EXCHANGE_TYPE_IKE_AUTH,
                            false /*isResponseMsg*/,
                            true /*fromIkeInitiator*/,
                            mCurrentIkeSaRecord.getLocalRequestMessageId());

            return new IkeMessage(ikeHeader, payloadList);
        }

        private void validateIkeAuthRespWithChildPayloads(IkeMessage respMsg)
                throws IkeProtocolException {
            // Extract and validate existence of payloads for first Child SA setup.
            List<IkePayload> childSaRespPayloads = extractChildPayloadsFromMessage(respMsg);

            List<IkePayload> nonChildPayloads = new LinkedList<>();
            nonChildPayloads.addAll(respMsg.ikePayloadList);
            nonChildPayloads.removeAll(childSaRespPayloads);

            validateIkeAuthResp(nonChildPayloads);
        }

        private void validateIkeAuthResp(List<IkePayload> payloadList) throws IkeProtocolException {
            // Validate IKE Authentication
            IkeIdPayload respIdPayload = null;
            IkeAuthPayload authPayload = null;
            List<IkeCertPayload> certPayloads = new LinkedList<>();

            for (IkePayload payload : payloadList) {
                switch (payload.payloadType) {
                    case IkePayload.PAYLOAD_TYPE_ID_RESPONDER:
                        respIdPayload = (IkeIdPayload) payload;
                        if (!mIkeSessionOptions
                                .getRemoteIdentification()
                                .equals(respIdPayload.ikeId)) {
                            throw new AuthenticationFailedException(
                                    "Unrecognized Responder Identification.");
                        }
                        break;
                    case IkePayload.PAYLOAD_TYPE_AUTH:
                        authPayload = (IkeAuthPayload) payload;
                        break;
                    case IkePayload.PAYLOAD_TYPE_CERT:
                        certPayloads.add((IkeCertPayload) payload);
                        break;
                    case IkePayload.PAYLOAD_TYPE_NOTIFY:
                        IkeNotifyPayload notifyPayload = (IkeNotifyPayload) payload;
                        if (notifyPayload.isErrorNotify()) {
                            // TODO: Throw IkeExceptions according to error types.
                            throw new UnsupportedOperationException(
                                    "Do not support handling error notifications in IKE AUTH"
                                            + " response.");
                        } else {
                            // Unknown and unexpected status notifications are ignored as per
                            // RFC7296.
                            logw(
                                    "Received unknown or unexpected status notifications with"
                                            + " notify type: "
                                            + notifyPayload.notifyType);
                        }

                    default:
                        throw new InvalidSyntaxException(
                                "Received unexpected payload in IKE AUTH response. Payload"
                                        + " type: "
                                        + payload);
                }
            }

            // Verify existence of payloads
            if (respIdPayload == null || authPayload == null) {
                throw new AuthenticationFailedException("ID-Responder or Auth payload is missing.");
            }

            // Autheticate the remote peer.
            authenticate(authPayload, respIdPayload, certPayloads);
        }

        private List<IkePayload> extractChildPayloadsFromMessage(IkeMessage ikeMessage)
                throws InvalidSyntaxException {
            IkeSaPayload saPayload =
                    ikeMessage.getPayloadForType(IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
            IkeTsPayload tsInitPayload =
                    ikeMessage.getPayloadForType(
                            IkePayload.PAYLOAD_TYPE_TS_INITIATOR, IkeTsPayload.class);
            IkeTsPayload tsRespPayload =
                    ikeMessage.getPayloadForType(
                            IkePayload.PAYLOAD_TYPE_TS_RESPONDER, IkeTsPayload.class);

            List<IkeNotifyPayload> notifyPayloads =
                    ikeMessage.getPayloadListForType(
                            IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);

            boolean hasErrorNotify = false;
            List<IkePayload> list = new LinkedList<>();
            for (IkeNotifyPayload payload : notifyPayloads) {
                if (payload.isNewChildSaNotify()) {
                    list.add(payload);
                    if (payload.isErrorNotify()) {
                        hasErrorNotify = true;
                    }
                }
            }

            // If there is no error notification, SA, TS-initiator and TS-responder MUST all be
            // included in this message.
            if (!hasErrorNotify
                    && (saPayload == null || tsInitPayload == null || tsRespPayload == null)) {
                throw new InvalidSyntaxException(
                        "SA, TS-Initiator or TS-Responder payload is missing.");
            }

            list.add(saPayload);
            list.add(tsInitPayload);
            list.add(tsRespPayload);
            return list;
        }

        private void authenticate(
                IkeAuthPayload authPayload,
                IkeIdPayload respIdPayload,
                List<IkeCertPayload> certPayloads)
                throws AuthenticationFailedException {
            switch (mIkeSessionOptions.getRemoteAuthConfig().mAuthMethod) {
                case IkeSessionOptions.IKE_AUTH_METHOD_PSK:
                    if (authPayload.authMethod != IkeAuthPayload.AUTH_METHOD_PRE_SHARED_KEY) {
                        throw new AuthenticationFailedException(
                                "Expected the remote server to use PSK-based authentication but"
                                        + " they used: "
                                        + authPayload.authMethod);
                    }
                    IkeAuthPskPayload pskPayload = (IkeAuthPskPayload) authPayload;
                    pskPayload.verifyInboundSignature(
                            mIkeSessionOptions.getRemoteAuthConfig().mPsk,
                            mIkeInitResponseBytes,
                            mCurrentIkeSaRecord.nonceInitiator,
                            respIdPayload.getEncodedPayloadBody(),
                            mIkePrf,
                            mCurrentIkeSaRecord.getSkPr());
                    break;
                case IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE:
                    // TODO: Support PUB_KEY_SIGNATURE
                    throw new UnsupportedOperationException(
                            "Do not support public-key based authentication.");
                default:
                    throw new IllegalArgumentException(
                            "Unrecognized auth method: " + authPayload.authMethod);
            }
        }

        @Override
        public void exit() {
            mRetransmitter.stopRetransmitting();
        }
    }

    // TODO: Add CreateIkeLocalIkeAuthInEap and CreateIkeLocalIkeAuthPostEap states.

    private abstract class RekeyIkeHandlerBase extends DeleteResponderBase {
        private void validateIkeRekeyCommon(IkeMessage ikeMessage) throws InvalidSyntaxException {
            boolean hasSaPayload = false;
            boolean hasKePayload = false;
            boolean hasNoncePayload = false;
            for (IkePayload payload : ikeMessage.ikePayloadList) {
                switch (payload.payloadType) {
                    case IkePayload.PAYLOAD_TYPE_SA:
                        hasSaPayload = true;
                        break;
                    case IkePayload.PAYLOAD_TYPE_KE:
                        hasKePayload = true;
                        break;
                    case IkePayload.PAYLOAD_TYPE_NONCE:
                        hasNoncePayload = true;
                        break;
                    case IkePayload.PAYLOAD_TYPE_VENDOR:
                        // Vendor payloads allowed, but not verified
                        break;
                    case IkePayload.PAYLOAD_TYPE_NOTIFY:
                        // Notification payloads allowed, but left to handler methods to process.
                        break;
                    default:
                        throw new InvalidSyntaxException(
                                "Received unexpected payload in IKE REKEY request. Payload type: "
                                        + payload.payloadType);
                }
            }

            if (!hasSaPayload || !hasKePayload || !hasNoncePayload) {
                throw new InvalidSyntaxException("SA, KE or Nonce payload missing.");
            }
        }

        @VisibleForTesting
        void validateIkeRekeyReq(IkeMessage ikeMessage) throws InvalidSyntaxException {
            // TODO: Validate it against mIkeSessionOptions.

            int exchangeType = ikeMessage.ikeHeader.exchangeType;
            if (exchangeType != IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA) {
                throw new InvalidSyntaxException(
                        "Expected EXCHANGE_TYPE_CREATE_CHILD_SA but received: " + exchangeType);
            }
            if (ikeMessage.ikeHeader.isResponseMsg) {
                throw new IllegalArgumentException("Invalid IKE Rekey request - was a response.");
            }

            List<IkeNotifyPayload> notificationPayloads =
                    ikeMessage.getPayloadListForType(
                            IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);
            for (IkeNotifyPayload notifyPayload : notificationPayloads) {
                if (notifyPayload.isErrorNotify()) {
                    throw new InvalidSyntaxException("Error notifications invalid in request");
                }
            }

            validateIkeRekeyCommon(ikeMessage);
        }

        @VisibleForTesting
        void validateIkeRekeyResp(IkeMessage reqMsg, IkeMessage respMsg)
                throws InvalidSyntaxException {
            int exchangeType = respMsg.ikeHeader.exchangeType;
            if (exchangeType != IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA
                    && exchangeType != IkeHeader.EXCHANGE_TYPE_INFORMATIONAL) {
                throw new InvalidSyntaxException(
                        "Expected Rekey response (CREATE_CHILD_SA or INFORMATIONAL) but received: "
                                + exchangeType);
            }
            if (!respMsg.ikeHeader.isResponseMsg) {
                throw new IllegalArgumentException("Invalid IKE Rekey response - was a request.");
            }

            List<IkeNotifyPayload> notificationPayloads =
                    respMsg.getPayloadListForType(
                            IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class);
            for (IkeNotifyPayload notifyPayload : notificationPayloads) {
                if (notifyPayload.isErrorNotify()) {
                    throw new UnsupportedOperationException(
                            "Error notifications not yet supported in rekey responses");
                }
            }

            validateIkeRekeyCommon(respMsg);

            // Verify DH groups matching
            IkeKePayload reqKePayload =
                    reqMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);
            IkeKePayload respKePayload =
                    respMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);
            if (reqKePayload.dhGroup != respKePayload.dhGroup) {
                throw new InvalidSyntaxException("Received KE payload with mismatched DH group.");
            }
        }

        protected IkeSaRecord validateAndBuildIkeSa(
                IkeMessage reqMsg, IkeMessage respMessage, boolean isLocalInit)
                throws IkeProtocolException, GeneralSecurityException, IOException {
            InetAddress initAddr = isLocalInit ? mLocalAddress : mRemoteAddress;
            InetAddress respAddr = isLocalInit ? mRemoteAddress : mLocalAddress;

            IkeSaPayload reqSaPayload =
                    reqMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
            IkeSaPayload respSaPayload =
                    respMessage.getPayloadForType(IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
            Pair<IkeProposal, IkeProposal> negotiatedProposals =
                    IkeSaPayload.getVerifiedNegotiatedIkeProposalPair(
                            reqSaPayload, respSaPayload, mRemoteAddress);
            IkeProposal reqProposal = negotiatedProposals.first;
            IkeProposal respProposal = negotiatedProposals.second;

            Provider provider = IkeMessage.getSecurityProvider();
            IkeMacPrf newPrf;
            IkeCipher newCipher;
            IkeMacIntegrity newIntegrity = null;

            newCipher =
                    IkeCipher.create(
                            respProposal.saProposal.getEncryptionTransforms()[0], provider);
            if (!newCipher.isAead()) {
                newIntegrity =
                        IkeMacIntegrity.create(
                                respProposal.saProposal.getIntegrityTransforms()[0], provider);
            }
            newPrf = IkeMacPrf.create(respProposal.saProposal.getPrfTransforms()[0], provider);

            // Build new SaRecord
            IkeSaRecord newSaRecord =
                    IkeSaRecord.makeRekeyedIkeSaRecord(
                            mCurrentIkeSaRecord,
                            mIkePrf,
                            reqMsg,
                            respMessage,
                            reqProposal.getIkeSpiResource(),
                            respProposal.getIkeSpiResource(),
                            newPrf,
                            newIntegrity == null ? 0 : newIntegrity.getKeyLength(),
                            newCipher.getKeyLength(),
                            isLocalInit);
            addIkeSaRecord(newSaRecord);

            mIkeCipher = newCipher;
            mIkePrf = newPrf;
            mIkeIntegrity = newIntegrity;

            return newSaRecord;
        }
    }

    /** RekeyIkeLocalCreate represents state when IKE library initiates Rekey IKE exchange. */
    class RekeyIkeLocalCreate extends RekeyIkeHandlerBase {
        protected Retransmitter mRetransmitter;

        @Override
        public void enter() {
            // TODO: Give mRetransmitter an actual request once buildIkeRekeyReq is implemented
            try {
                mRetransmitter = new Retransmitter(buildIkeRekeyReq());
            } catch (IOException e) {
                // TODO: Schedule next rekey for RETRY_TIMEOUT

                // Attempt to recover by retrying (until hard lifetime).
                transitionTo(mIdle);
            }
        }

        /**
         * Builds a IKE Rekey request, reusing the current proposal
         *
         * <p>As per RFC 7296, rekey messages are of format: { HDR { SK { SA, Ni, KEi } } }
         *
         * <p>This method currently reuses agreed upon proposal.
         */
        private IkeMessage buildIkeRekeyReq() throws IOException {
            // TODO: Evaluate if we need to support different proposals for rekeys
            SaProposal[] saProposals = new SaProposal[] {mSaProposal};

            // No need to allocate SPIs; they will be allocated as part of the
            // getRekeyIkeSaRequestPayloads
            List<IkePayload> payloadList =
                    CreateIkeSaHelper.getRekeyIkeSaRequestPayloads(saProposals, mLocalAddress);

            // Build IKE header
            IkeHeader ikeHeader =
                    new IkeHeader(
                            mCurrentIkeSaRecord.getInitiatorSpi(),
                            mCurrentIkeSaRecord.getResponderSpi(),
                            IkePayload.PAYLOAD_TYPE_SK,
                            IkeHeader.EXCHANGE_TYPE_CREATE_CHILD_SA,
                            false /*isResponseMsg*/,
                            mCurrentIkeSaRecord.isLocalInit,
                            mCurrentIkeSaRecord.getLocalRequestMessageId());

            return new IkeMessage(ikeHeader, payloadList);
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    handleDeleteSessionRequest(ikeMessage);
                    break;
                default:
                    // TODO: Implement simultaneous rekey
                    IkeInformationalPayload error =
                            new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE);
                    IkeMessage msg =
                            buildEncryptedNotificationMessage(
                                    mCurrentIkeSaRecord,
                                    new IkeInformationalPayload[] {error},
                                    ikeMessage.ikeHeader.exchangeType,
                                    true,
                                    ikeMessage.ikeHeader.messageId);

                    sendEncryptedIkeMessage(msg);
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                validateIkeRekeyResp(mRetransmitter.getMessage(), ikeMessage);
                mLocalInitNewIkeSaRecord =
                        validateAndBuildIkeSa(
                                mRetransmitter.getMessage(), ikeMessage, true /*isLocalInit*/);
                transitionTo(mRekeyIkeLocalDelete);

                // Stop retransmissions
                mRetransmitter.stopRetransmitting();
            } catch (IkeProtocolException e) {
                // TODO: Handle processing errors.
            } catch (GeneralSecurityException e) {
                // TODO: Fatal - kill session.
            } catch (IOException e) {
                // TODO: SPI allocation collided - delete new IKE SA, retry rekey.
            }
        }
    }

    /**
     * SimulRekeyIkeLocalCreate represents the state where IKE library has replied to rekey request
     * sent from the remote and is waiting for a rekey response for a locally initiated rekey
     * request.
     *
     * <p>SimulRekeyIkeLocalCreate extends RekeyIkeLocalCreate so that it can call super class to
     * validate incoming rekey response against locally initiated rekey request.
     */
    class SimulRekeyIkeLocalCreate extends RekeyIkeLocalCreate {
        @Override
        public void enter() {
            super.mRetransmitter = new Retransmitter(null);
            // TODO: Populate super.mRetransmitter from state initialization data
            // Do not send request.
        }

        public IkeMessage buildRequest() {
            throw new UnsupportedOperationException(
                    "Do not support sending request in " + getCurrentState().getName());
        }

        @Override
        public void exit() {
            // Do nothing.
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_IKE_PACKET:
                    ReceivedIkePacket receivedIkePacket = (ReceivedIkePacket) message.obj;
                    IkeHeader ikeHeader = receivedIkePacket.ikeHeader;

                    if (mRemoteInitNewIkeSaRecord == getIkeSaRecordForPacket(ikeHeader)) {
                        deferMessage(message);
                    } else {
                        handleReceivedIkePacket(message);
                    }
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    deferMessage(message);
                    return;
                default:
                    // TODO: Add more cases for other types of request.
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                validateIkeRekeyResp(mRetransmitter.getMessage(), ikeMessage);
                mLocalInitNewIkeSaRecord =
                        validateAndBuildIkeSa(
                                mRetransmitter.getMessage(), ikeMessage, true /*isLocalInit*/);
                transitionTo(mSimulRekeyIkeLocalDeleteRemoteDelete);
            } catch (IkeProtocolException e) {
                // TODO: Handle processing errors.
            } catch (GeneralSecurityException e) {
                // TODO: Fatal - kill session.
            } catch (IOException e) {
                // TODO: SPI allocation collided - delete new IKE SA, retry rekey.
            }
        }
    }

    /** RekeyIkeDeleteBase represents common behaviours of deleting stage during rekeying IKE SA. */
    private abstract class RekeyIkeDeleteBase extends DeleteBase {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_IKE_PACKET:
                    ReceivedIkePacket receivedIkePacket = (ReceivedIkePacket) message.obj;
                    IkeHeader ikeHeader = receivedIkePacket.ikeHeader;

                    // Verify that this message is correctly authenticated and encrypted:
                    IkeSaRecord ikeSaRecord = getIkeSaRecordForPacket(ikeHeader);
                    boolean isMessageOnNewSa = false;
                    if (ikeSaRecord != null && mIkeSaRecordSurviving == ikeSaRecord) {
                        DecodeResult decodeResult =
                                IkeMessage.decode(
                                        ikeHeader.isResponseMsg
                                                ? ikeSaRecord.getLocalRequestMessageId()
                                                : ikeSaRecord.getRemoteRequestMessageId(),
                                        mIkeIntegrity,
                                        mIkeCipher,
                                        ikeSaRecord,
                                        ikeHeader,
                                        receivedIkePacket.ikePacketBytes);
                        isMessageOnNewSa =
                                (decodeResult.status == DECODE_STATUS_PROTECTED_ERROR_MESSAGE)
                                        || (decodeResult.status == DECODE_STATUS_OK);
                    }

                    // Authenticated request received on the new/surviving SA; treat it as
                    // an acknowledgement that the remote has successfully rekeyed.
                    if (isMessageOnNewSa) {
                        State nextState = mIdle;

                        // This is the first IkeMessage seen on the new SA. It cannot be a response.
                        // Likewise, if it a request, it must not be a retransmission. Verify msgId.
                        // If either condition happens, consider rekey a success, but immediately
                        // kill the session.
                        if (ikeHeader.isResponseMsg
                                || ikeSaRecord.getRemoteRequestMessageId() - ikeHeader.messageId
                                        != 0) {
                            nextState = mDeleteIkeLocalDelete;
                        } else {
                            deferMessage(message);
                        }

                        // Locally close old (and losing) IKE SAs. As a result of not waiting for
                        // delete responses, the old SA can be left in a state where the stored ID
                        // is no longer correct. However, this finishRekey() call will remove that
                        // SA, so it doesn't matter.
                        finishRekey();
                        transitionTo(nextState);
                    } else {
                        handleReceivedIkePacket(message);
                    }

                    return HANDLED;
                default:
                    return super.processMessage(message);
                    // TODO: Add more cases for other packet types.
            }
        }

        protected void finishRekey() {
            mCurrentIkeSaRecord = mIkeSaRecordSurviving;
            mLocalInitNewIkeSaRecord = null;
            mRemoteInitNewIkeSaRecord = null;

            mIkeSaRecordSurviving = null;

            if (mIkeSaRecordAwaitingLocalDel != null) {
                removeIkeSaRecord(mIkeSaRecordAwaitingLocalDel);
                mIkeSaRecordAwaitingLocalDel.close();
                mIkeSaRecordAwaitingLocalDel = null;
            }

            if (mIkeSaRecordAwaitingRemoteDel != null) {
                removeIkeSaRecord(mIkeSaRecordAwaitingRemoteDel);
                mIkeSaRecordAwaitingRemoteDel.close();
                mIkeSaRecordAwaitingRemoteDel = null;
            }
        }
    }

    /**
     * SimulRekeyIkeLocalDeleteRemoteDelete represents the deleting stage during simultaneous
     * rekeying when IKE library is waiting for both a Delete request and a Delete response.
     */
    class SimulRekeyIkeLocalDeleteRemoteDelete extends RekeyIkeDeleteBase {
        private Retransmitter mRetransmitter;

        @Override
        public void enter() {
            // Detemine surviving IKE SA. According to RFC 7296: "The new IKE SA containing the
            // lowest nonce SHOULD be deleted by the node that created it, and the other surviving
            // new IKE SA MUST inherit all the Child SAs."
            if (mLocalInitNewIkeSaRecord.compareTo(mRemoteInitNewIkeSaRecord) > 0) {
                mIkeSaRecordSurviving = mLocalInitNewIkeSaRecord;
                mIkeSaRecordAwaitingLocalDel = mCurrentIkeSaRecord;
                mIkeSaRecordAwaitingRemoteDel = mRemoteInitNewIkeSaRecord;
            } else {
                mIkeSaRecordSurviving = mRemoteInitNewIkeSaRecord;
                mIkeSaRecordAwaitingLocalDel = mLocalInitNewIkeSaRecord;
                mIkeSaRecordAwaitingRemoteDel = mCurrentIkeSaRecord;
            }
            mRetransmitter = new Retransmitter(buildIkeDeleteReq(mIkeSaRecordAwaitingLocalDel));
            // TODO: Set timer awaiting for delete request.
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            IkeSaRecord ikeSaRecordForPacket = getIkeSaRecordForPacket(ikeMessage.ikeHeader);
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    try {
                        validateIkeDeleteReq(ikeMessage, mIkeSaRecordAwaitingRemoteDel);
                        IkeMessage respMsg =
                                buildIkeDeleteResp(ikeMessage, mIkeSaRecordAwaitingRemoteDel);
                        removeIkeSaRecord(mIkeSaRecordAwaitingRemoteDel);
                        // TODO: Encode and send response and close
                        // mIkeSaRecordAwaitingRemoteDel.
                        // TODO: Stop timer awating delete request.
                        transitionTo(mSimulRekeyIkeLocalDelete);
                    } catch (InvalidSyntaxException e) {
                        Log.d(TAG, "Validation failed for delete request", e);
                        // TODO: Shutdown - fatal error
                    }
                    return;
                default:
                    // TODO: Reply with TEMPORARY_FAILURE
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                validateIkeDeleteResp(ikeMessage, mIkeSaRecordAwaitingLocalDel);

                transitionTo(mSimulRekeyIkeRemoteDelete);
                removeIkeSaRecord(mIkeSaRecordAwaitingLocalDel);
                // TODO: Close mIkeSaRecordAwaitingLocalDel
                mRetransmitter.stopRetransmitting();
            } catch (InvalidSyntaxException e) {
                Log.d(TAG, "Validation failed for delete response", e);
                // TODO: Shutdown - fatal error
            }
        }

        @Override
        public void exit() {
            finishRekey();
            mRetransmitter.stopRetransmitting();
            // TODO: Stop awaiting delete request timer.
        }
    }

    /**
     * SimulRekeyIkeLocalDelete represents the state when IKE library is waiting for a Delete
     * response during simultaneous rekeying.
     */
    class SimulRekeyIkeLocalDelete extends RekeyIkeDeleteBase {
        private Retransmitter mRetransmitter;

        @Override
        public void enter() {
            mRetransmitter = new Retransmitter(null);
            // TODO: Populate mRetransmitter from state initialization data.
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            // Always return a TEMPORARY_FAILURE. In no case should we accept a message on an SA
            // that is going away. All messages on the new SA is caught in RekeyIkeDeleteBase
            IkeInformationalPayload error =
                    new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE);
            IkeMessage msg =
                    buildEncryptedNotificationMessage(
                            mIkeSaRecordAwaitingLocalDel,
                            new IkeInformationalPayload[] {error},
                            ikeMessage.ikeHeader.exchangeType,
                            true,
                            ikeMessage.ikeHeader.messageId);

            sendEncryptedIkeMessage(msg);
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                validateIkeDeleteResp(ikeMessage, mIkeSaRecordAwaitingLocalDel);

                finishRekey();
                transitionTo(mIdle);
            } catch (InvalidSyntaxException e) {
                Log.d(TAG, "Validation failed for delete response", e);
                // TODO: Shutdown
            }
        }
    }

    /**
     * SimulRekeyIkeRemoteDelete represents the state that waiting for a Delete request during
     * simultaneous rekeying.
     */
    class SimulRekeyIkeRemoteDelete extends RekeyIkeDeleteBase {
        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    try {
                        validateIkeDeleteReq(ikeMessage, mIkeSaRecordAwaitingRemoteDel);

                        IkeMessage respMsg =
                                buildIkeDeleteResp(ikeMessage, mIkeSaRecordAwaitingRemoteDel);
                        sendEncryptedIkeMessage(mIkeSaRecordAwaitingRemoteDel, respMsg);

                        finishRekey();
                        transitionTo(mIdle);
                    } catch (InvalidSyntaxException e) {
                        // TODO: The other side deleted the wrong IKE SA and we should close the
                        // whole IKE session.
                    }
                    return;
                default:
                    // At this point, the incoming request can ONLY be on
                    // mIkeSaRecordAwaitingRemoteDel - if it was on the surviving SA, it is defered
                    // and the rekey is finished. It is likewise impossible to have this on the
                    // local-deleted SA, since the delete has already been acknowledged in the
                    // SimulRekeyIkeLocalDeleteRemoteDelete state.
                    IkeInformationalPayload error =
                            new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE);
                    IkeMessage msg =
                            buildEncryptedNotificationMessage(
                                    mIkeSaRecordAwaitingRemoteDel,
                                    new IkeInformationalPayload[] {error},
                                    ikeMessage.ikeHeader.exchangeType,
                                    true,
                                    ikeMessage.ikeHeader.messageId);

                    sendEncryptedIkeMessage(msg);
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            Log.wtf(
                    TAG,
                    "State: "
                            + getCurrentState().getName()
                            + "received an unsupported response message.");
        }
    }

    /**
     * RekeyIkeLocalDelete represents the deleting stage when IKE library is initiating a Rekey
     * procedure.
     *
     * <p>RekeyIkeLocalDelete and SimulRekeyIkeLocalDelete have same behaviours in processMessage().
     * While RekeyIkeLocalDelete overrides enter() and exit() methods for initiating and finishing
     * the deleting stage for IKE rekeying.
     */
    class RekeyIkeLocalDelete extends SimulRekeyIkeLocalDelete {
        private Retransmitter mRetransmitter;

        @Override
        public void enter() {
            mIkeSaRecordSurviving = mLocalInitNewIkeSaRecord;
            mIkeSaRecordAwaitingLocalDel = mCurrentIkeSaRecord;
            mRetransmitter = new Retransmitter(buildIkeDeleteReq(mIkeSaRecordAwaitingLocalDel));
        }

        @Override
        public void exit() {
            mRetransmitter.stopRetransmitting();
        }
    }

    /**
     * RekeyIkeRemoteDelete represents the deleting stage when responding to a Rekey procedure.
     *
     * <p>RekeyIkeRemoteDelete and SimulRekeyIkeRemoteDelete have same behaviours in
     * processMessage(). While RekeyIkeLocalDelete overrides enter() and exit() methods for waiting
     * incoming delete request and for finishing the deleting stage for IKE rekeying.
     */
    class RekeyIkeRemoteDelete extends SimulRekeyIkeRemoteDelete {
        @Override
        public void enter() {
            mIkeSaRecordSurviving = mRemoteInitNewIkeSaRecord;
            mIkeSaRecordAwaitingRemoteDel = mCurrentIkeSaRecord;

            sendMessageDelayed(TIMEOUT_REKEY_REMOTE_DELETE_IKE, REKEY_DELETE_TIMEOUT_MS);
        }

        @Override
        public boolean processMessage(Message message) {
            // Intercept rekey delete timeout. Assume rekey succeeded since no retransmissions
            // were received.
            if (message.what == TIMEOUT_REKEY_REMOTE_DELETE_IKE) {
                finishRekey();
                transitionTo(mIdle);

                return HANDLED;
            } else {
                return super.processMessage(message);
            }
        }

        @Override
        public void exit() {
            removeMessages(TIMEOUT_REKEY_REMOTE_DELETE_IKE);
        }
    }

    /** DeleteIkeLocalDelete initiates a deletion request of the current IKE Session. */
    class DeleteIkeLocalDelete extends DeleteBase {
        private Retransmitter mRetransmitter;

        @Override
        public void enter() {
            mRetransmitter = new Retransmitter(buildIkeDeleteReq(mCurrentIkeSaRecord));
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    handleDeleteSessionRequest(ikeMessage);
                    return;
                default:
                    IkeInformationalPayload error =
                            new IkeNotifyPayload(IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE);
                    IkeMessage msg =
                            buildEncryptedNotificationMessage(
                                    mCurrentIkeSaRecord,
                                    new IkeInformationalPayload[] {error},
                                    ikeMessage.ikeHeader.exchangeType,
                                    true,
                                    ikeMessage.ikeHeader.messageId);

                    sendEncryptedIkeMessage(msg);
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                validateIkeDeleteResp(ikeMessage, mCurrentIkeSaRecord);
            } catch (InvalidSyntaxException e) {
                Log.d(TAG, "Invalid syntax on IKE Delete response. Shutting down anyways", e);
            }

            removeIkeSaRecord(mCurrentIkeSaRecord);
            mCurrentIkeSaRecord.close();
            mCurrentIkeSaRecord = null;

            transitionTo(mClosed);
        }

        @Override
        public void exit() {
            mRetransmitter.stopRetransmitting();
        }
    }

    /**
     * Helper class to generate IKE SA creation payloads, in both request and response directions.
     */
    private static class CreateIkeSaHelper {
        public static List<IkePayload> getIkeInitSaRequestPayloads(
                SaProposal[] saProposals,
                long initIkeSpi,
                long respIkeSpi,
                InetAddress localAddr,
                InetAddress remoteAddr,
                int localPort,
                int remotePort)
                throws IOException {
            List<IkePayload> payloadList =
                    getCreateIkeSaPayloads(IkeSaPayload.createInitialIkeSaPayload(saProposals));

            // Though RFC says Notify-NAT payload is "just after the Ni and Nr payloads (before the
            // optional CERTREQ payload)", it also says recipient MUST NOT reject " messages in
            // which the payloads were not in the "right" order" due to the lack of clarity of the
            // payload order.
            payloadList.add(
                    new IkeNotifyPayload(
                            NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP,
                            IkeNotifyPayload.generateNatDetectionData(
                                    initIkeSpi, respIkeSpi, localAddr, localPort)));
            payloadList.add(
                    new IkeNotifyPayload(
                            NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP,
                            IkeNotifyPayload.generateNatDetectionData(
                                    initIkeSpi, respIkeSpi, remoteAddr, remotePort)));
            return payloadList;
        }

        public static List<IkePayload> getRekeyIkeSaRequestPayloads(
                SaProposal[] saProposals, InetAddress localAddr) throws IOException {
            if (localAddr == null) {
                throw new IllegalArgumentException("Local address was null for rekey");
            }

            return getCreateIkeSaPayloads(
                    IkeSaPayload.createRekeyIkeSaRequestPayload(saProposals, localAddr));
        }

        public static List<IkePayload> getRekeyIkeSaResponsePayloads(
                byte respProposalNumber, SaProposal saProposal, InetAddress localAddr)
                throws IOException {
            if (localAddr == null) {
                throw new IllegalArgumentException("Local address was null for rekey");
            }

            return getCreateIkeSaPayloads(
                    IkeSaPayload.createRekeyIkeSaResponsePayload(
                            respProposalNumber, saProposal, localAddr));
        }

        /**
         * Builds the initial or rekey IKE creation payloads.
         *
         * <p>Will return a non-empty list of IkePayloads, the first of which WILL be the SA payload
         */
        private static List<IkePayload> getCreateIkeSaPayloads(IkeSaPayload saPayload)
                throws IOException {
            if (saPayload.proposalList.size() == 0) {
                throw new IllegalArgumentException("Invalid SA proposal list - was empty");
            }

            List<IkePayload> payloadList = new ArrayList<>(3);

            payloadList.add(saPayload);
            payloadList.add(new IkeNoncePayload());

            // SaPropoals.Builder guarantees that each SA proposal has at least one DH group.
            DhGroupTransform dhGroupTransform =
                    saPayload.proposalList.get(0).saProposal.getDhGroupTransforms()[0];
            payloadList.add(new IkeKePayload(dhGroupTransform.id));

            return payloadList;
        }
    }
}
