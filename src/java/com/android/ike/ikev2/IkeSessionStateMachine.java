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

import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_CHILD_SA_NOT_FOUND;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_MAJOR_VERSION;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_INVALID_SYNTAX;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_NO_ADDITIONAL_SAS;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_TEMPORARY_FAILURE;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;
import static com.android.ike.ikev2.exceptions.IkeProtocolException.ErrorType;
import static com.android.ike.ikev2.message.IkeHeader.EXCHANGE_TYPE_INFORMATIONAL;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_OK;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_PROTECTED_ERROR_MESSAGE;
import static com.android.ike.ikev2.message.IkeMessage.DECODE_STATUS_UNPROTECTED_ERROR_MESSAGE;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP;
import static com.android.ike.ikev2.message.IkeNotifyPayload.NOTIFY_TYPE_REKEY_SA;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_CP;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_DELETE;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_NOTIFY;
import static com.android.ike.ikev2.message.IkePayload.PAYLOAD_TYPE_VENDOR;

import android.annotation.IntDef;
import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Looper;
import android.os.Message;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import android.util.LongSparseArray;
import android.util.Pair;
import android.util.SparseArray;

import com.android.ike.eap.EapAuthenticator;
import com.android.ike.eap.IEapCallback;
import com.android.ike.ikev2.ChildSessionStateMachine.CreateChildSaHelper;
import com.android.ike.ikev2.IkeLocalRequestScheduler.ChildLocalRequest;
import com.android.ike.ikev2.IkeLocalRequestScheduler.LocalRequest;
import com.android.ike.ikev2.IkeSessionOptions.IkeAuthConfig;
import com.android.ike.ikev2.IkeSessionOptions.IkeAuthPskConfig;
import com.android.ike.ikev2.SaRecord.IkeSaRecord;
import com.android.ike.ikev2.crypto.IkeCipher;
import com.android.ike.ikev2.crypto.IkeMacIntegrity;
import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.exceptions.AuthenticationFailedException;
import com.android.ike.ikev2.exceptions.IkeInternalException;
import com.android.ike.ikev2.exceptions.IkeProtocolException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.message.IkeAuthPayload;
import com.android.ike.ikev2.message.IkeAuthPskPayload;
import com.android.ike.ikev2.message.IkeCertPayload;
import com.android.ike.ikev2.message.IkeDeletePayload;
import com.android.ike.ikev2.message.IkeEapPayload;
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
import com.android.ike.ikev2.utils.Retransmitter;
import com.android.internal.annotations.GuardedBy;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/**
 * IkeSessionStateMachine tracks states and manages exchanges of this IKE session.
 *
 * <p>IkeSessionStateMachine has two types of states. One type are states where there is no ongoing
 * procedure affecting IKE session (non-procedure state), including Initial, Idle and Receiving. All
 * other states are "procedure" states which are named as follows:
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

    // TODO: Add SA_HARD_LIFETIME_MS

    // Time after which IKE SA needs to be rekeyed
    @VisibleForTesting static final long SA_SOFT_LIFETIME_MS = TimeUnit.HOURS.toMillis(3L);

    // TODO: Allow users to configure IKE lifetime

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
    /** Trigger a retransmission. */
    public static final int CMD_RETRANSMIT = CMD_GENERAL_BASE + 8;
    /** Send EAP request payloads to EapAuthenticator for further processing. */
    static final int CMD_EAP_START_EAP_AUTH = CMD_GENERAL_BASE + 9;
    /** Send the outbound IKE-wrapped EAP-Response message. */
    static final int CMD_EAP_OUTBOUND_MSG_READY = CMD_GENERAL_BASE + 10;
    /** Proxy to IkeSessionStateMachine handler to notify of errors */
    static final int CMD_EAP_ERRORED = CMD_GENERAL_BASE + 11;
    /** Proxy to IkeSessionStateMachine handler to notify of failures */
    static final int CMD_EAP_FAILED = CMD_GENERAL_BASE + 12;
    /** Proxy to IkeSessionStateMachine handler to notify of success, to continue to post-auth */
    static final int CMD_EAP_FINISH_EAP_AUTH = CMD_GENERAL_BASE + 14;
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

    /** Map that stores all IkeSaRecords, keyed by locally generated IKE SPI. */
    private final LongSparseArray<IkeSaRecord> mLocalSpiToIkeSaRecordMap;
    /**
     * Map that stores all ChildSessionStateMachines, keyed by remotely generated Child SPI for
     * sending IPsec packet. Different SPIs may point to the same ChildSessionStateMachine if this
     * Child Session is doing Rekey.
     */
    private final SparseArray<ChildSessionStateMachine> mRemoteSpiToChildSessionMap;

    private final Context mContext;
    private final IpSecManager mIpSecManager;
    private final IkeLocalRequestScheduler mScheduler;
    private final Executor mUserCbExecutor;
    private final IIkeSessionCallback mIkeSessionCallback;
    private final IkeEapAuthenticatorFactory mEapAuthenticatorFactory;

    @VisibleForTesting
    @GuardedBy("mChildCbToSessions")
    final HashMap<IChildSessionCallback, ChildSessionStateMachine> mChildCbToSessions =
            new HashMap<>();

    @VisibleForTesting byte[] mLastReceivedIkeReq;
    @VisibleForTesting byte[] mLastSentIkeResp;

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

    // FIXME: b/131265898 Pass these parameters from CreateIkeLocalIkeAuth through to
    // CreateIkeLocalIkeAuthPostEap as entry data when Android StateMachine can support that.
    @VisibleForTesting IkeIdPayload mInitIdPayload;
    @VisibleForTesting IkeIdPayload mRespIdPayload;
    @VisibleForTesting List<IkePayload> mFirstChildReqList;

    // FIXME: b/131265898 Move into CreateIkeLocalIkeAuth, and pass through to
    // CreateIkeLocalIkeAuthPostEap once passing entry data is supported
    private ChildSessionOptions mFirstChildSessionOptions;
    private IChildSessionCallback mFirstChildCallbacks;

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
    @VisibleForTesting final State mIdle = new Idle();
    @VisibleForTesting final State mChildProcedureOngoing = new ChildProcedureOngoing();
    @VisibleForTesting final State mReceiving = new Receiving();
    @VisibleForTesting final State mCreateIkeLocalIkeInit = new CreateIkeLocalIkeInit();
    @VisibleForTesting final State mCreateIkeLocalIkeAuth = new CreateIkeLocalIkeAuth();
    @VisibleForTesting final State mCreateIkeLocalIkeAuthInEap = new CreateIkeLocalIkeAuthInEap();

    @VisibleForTesting
    final State mCreateIkeLocalIkeAuthPostEap = new CreateIkeLocalIkeAuthPostEap();

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

    // Testing constructor
    @VisibleForTesting
    IkeSessionStateMachine(
            Looper looper,
            Context context,
            IpSecManager ipSecManager,
            IkeSessionOptions ikeOptions,
            ChildSessionOptions firstChildOptions,
            Executor userCbExecutor,
            IIkeSessionCallback ikeSessionCallback,
            IChildSessionCallback firstChildSessionCallback,
            IkeEapAuthenticatorFactory eapAuthenticatorFactory) {
        super(TAG, looper);

        mIkeSessionOptions = ikeOptions;
        mEapAuthenticatorFactory = eapAuthenticatorFactory;

        // There are at most three IkeSaRecords co-existing during simultaneous rekeying.
        mLocalSpiToIkeSaRecordMap = new LongSparseArray<>(3);
        mRemoteSpiToChildSessionMap = new SparseArray<>();

        mContext = context;
        mIpSecManager = ipSecManager;

        mUserCbExecutor = userCbExecutor;
        mIkeSessionCallback = ikeSessionCallback;

        mFirstChildSessionOptions = firstChildOptions;
        mFirstChildCallbacks = firstChildSessionCallback;
        registerChildSessionCallback(firstChildOptions, firstChildSessionCallback, true);

        addState(mInitial);
        addState(mCreateIkeLocalIkeInit);
        addState(mCreateIkeLocalIkeAuth);
        addState(mCreateIkeLocalIkeAuthInEap);
        addState(mCreateIkeLocalIkeAuthPostEap);
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

        start();
    }

    /** Package private constructor */
    IkeSessionStateMachine(
            Looper looper,
            Context context,
            IpSecManager ipSecManager,
            IkeSessionOptions ikeOptions,
            ChildSessionOptions firstChildOptions,
            Executor userCbExecutor,
            IIkeSessionCallback ikeSessionCallback,
            IChildSessionCallback firstChildSessionCallback) {
        this(
                looper,
                context,
                ipSecManager,
                ikeOptions,
                firstChildOptions,
                userCbExecutor,
                ikeSessionCallback,
                firstChildSessionCallback,
                new IkeEapAuthenticatorFactory());
    }

    private boolean hasChildSessionCallback(IChildSessionCallback callback) {
        synchronized (mChildCbToSessions) {
            return mChildCbToSessions.containsKey(callback);
        }
    }

    /**
     * Synchronously builds and registers a child session.
     *
     * <p>Setup of the child state machines MUST be done in two stages to ensure that if an external
     * caller calls openChildSession and then calls closeChildSession before the state machine has
     * gotten a chance to negotiate the sessions, a valid callback mapping exists (and does not
     * throw an exception that the callback was not found).
     *
     * <p>In the edge case where a child creation fails, and deletes itself, all pending requests
     * will no longer find the session in the map. Assume it has errored/failed, and skip/ignore.
     * This is safe, as closeChildSession() (previously) validated that the callback was registered.
     */
    @VisibleForTesting
    void registerChildSessionCallback(
            ChildSessionOptions childOptions,
            IChildSessionCallback callbacks,
            boolean isFirstChild) {
        synchronized (mChildCbToSessions) {
            if (!isFirstChild && getCurrentState() == null) {
                throw new IllegalStateException(
                        "Request rejected because IKE Session is being closed. ");
            }

            mChildCbToSessions.put(
                    callbacks,
                    ChildSessionStateMachineFactory.makeChildSessionStateMachine(
                            getHandler().getLooper(),
                            mContext,
                            childOptions,
                            mUserCbExecutor,
                            callbacks,
                            new ChildSessionSmCallback()));
        }
    }

    void openChildSession(
            ChildSessionOptions childSessionOptions, IChildSessionCallback childSessionCallback) {
        if (childSessionCallback == null) {
            throw new IllegalArgumentException("Child Session Callback must be provided");
        }

        if (hasChildSessionCallback(childSessionCallback)) {
            throw new IllegalArgumentException("Child Session Callback handle already registered");
        }

        registerChildSessionCallback(
                childSessionOptions, childSessionCallback, false /*isFirstChild*/);
        sendMessage(
                CMD_LOCAL_REQUEST_CREATE_CHILD,
                new ChildLocalRequest(
                        CMD_LOCAL_REQUEST_CREATE_CHILD, childSessionCallback, childSessionOptions));
    }

    void closeChildSession(IChildSessionCallback childSessionCallback) {
        if (childSessionCallback == null) {
            throw new IllegalArgumentException("Child Session Callback must be provided");
        }

        if (!hasChildSessionCallback(childSessionCallback)) {
            throw new IllegalArgumentException("Child Session Callback handle not registered");
        }

        sendMessage(
                CMD_LOCAL_REQUEST_DELETE_CHILD,
                new ChildLocalRequest(CMD_LOCAL_REQUEST_DELETE_CHILD, childSessionCallback, null));
    }

    void closeSession() {
        sendMessage(CMD_LOCAL_REQUEST_DELETE_IKE, new LocalRequest(CMD_LOCAL_REQUEST_DELETE_IKE));
    }

    private void scheduleRekeySession(LocalRequest rekeyRequest) {
        // TODO: Make rekey timeout fuzzy
        sendMessageDelayed(CMD_LOCAL_REQUEST_REKEY_IKE, rekeyRequest, SA_SOFT_LIFETIME_MS);
    }

    // TODO: Support initiating Delete IKE exchange when IKE SA expires

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
        mLocalSpiToIkeSaRecordMap.put(record.getLocalSpi(), record);

        // In IKE_INIT exchange, local SPI was registered with this IkeSessionStateMachine before
        // IkeSaRecord is created. Calling this method at the end of exchange will double-register
        // the SPI but it is safe because the key and value are not changed.
        mIkeSocket.registerIke(record.getLocalSpi(), this);

        scheduleRekeySession(record.getFutureRekeyEvent());
    }

    @VisibleForTesting
    void removeIkeSaRecord(IkeSaRecord record) {
        mIkeSocket.unregisterIke(record.getLocalSpi());
        mLocalSpiToIkeSaRecordMap.remove(record.getLocalSpi());
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
        public final IChildSessionCallback childSessionCallback;
        public final List<IkePayload> reqPayloads;
        public final List<IkePayload> respPayloads;

        // TODO: Also store ChildSessionCallback

        FirstChildNegotiationData(
                ChildSessionOptions childSessionOptions,
                IChildSessionCallback childSessionCallback,
                List<IkePayload> reqPayloads,
                List<IkePayload> respPayloads) {
            this.childSessionOptions = childSessionOptions;
            this.childSessionCallback = childSessionCallback;
            this.reqPayloads = reqPayloads;
            this.respPayloads = respPayloads;
        }
    }

    /** Class to group parameters for building an outbound message for ChildSessions. */
    private static class ChildOutboundData {
        @ExchangeType public final int exchangeType;
        public final boolean isResp;
        public final List<IkePayload> payloadList;
        public final ChildSessionStateMachine childSession;

        ChildOutboundData(
                @ExchangeType int exchangeType,
                boolean isResp,
                List<IkePayload> payloadList,
                ChildSessionStateMachine childSession) {
            this.exchangeType = exchangeType;
            this.isResp = isResp;
            this.payloadList = payloadList;
            this.childSession = childSession;
        }
    }

    /** Callback for ChildSessionStateMachine to notify IkeSessionStateMachine. */
    @VisibleForTesting
    class ChildSessionSmCallback implements ChildSessionStateMachine.IChildSessionSmCallback {
        @Override
        public void onChildSaCreated(int remoteSpi, ChildSessionStateMachine childSession) {
            mRemoteSpiToChildSessionMap.put(remoteSpi, childSession);
        }

        @Override
        public void onChildSaDeleted(int remoteSpi) {
            mRemoteSpiToChildSessionMap.remove(remoteSpi);
        }

        @Override
        public void scheduleLocalRequest(ChildLocalRequest futureRequest, long delayedTime) {
            sendMessageDelayed(futureRequest.procedureType, futureRequest, delayedTime);
        }

        @Override
        public void onOutboundPayloadsReady(
                @ExchangeType int exchangeType,
                boolean isResp,
                List<IkePayload> payloadList,
                ChildSessionStateMachine childSession) {
            sendMessage(
                    CMD_OUTBOUND_CHILD_PAYLOADS_READY,
                    new ChildOutboundData(exchangeType, isResp, payloadList, childSession));
        }

        @Override
        public void onProcedureFinished(ChildSessionStateMachine childSession) {
            if (getHandler() == null) {
                // If the state machine has quit (because IKE Session is being closed), do not send
                // any message.
                return;
            }

            sendMessage(CMD_CHILD_PROCEDURE_FINISHED, childSession);
        }

        @Override
        public void onChildSessionClosed(IChildSessionCallback userCallbacks) {
            synchronized (mChildCbToSessions) {
                mChildCbToSessions.remove(userCallbacks);
            }
        }

        @Override
        public void onFatalIkeSessionError(boolean needsNotifyRemote) {
            // TODO: If needsNotifyRemote is true, send a Delete IKE request and then kill the IKE
            // Session. Otherwise, directly kill the IKE Session.
        }
    }

    /**
     * Top level state for handling uncaught exceptions for all subclasses.
     *
     * <p>All other state MUST extend this state.
     *
     * <p>Only errors this state should catch are unexpected internal failures. Since this may be
     * run in critical processes, it must never take down the process if it fails
     */
    abstract class ExceptionHandler extends State {
        @Override
        public final void enter() {
            try {
                enterState();
            } catch (RuntimeException e) {
                cleanUpAndQuit(e);
            }
        }

        @Override
        public final boolean processMessage(Message message) {
            try {
                return processStateMessage(message);
            } catch (RuntimeException e) {
                cleanUpAndQuit(e);
                return HANDLED;
            }
        }

        @Override
        public final void exit() {
            try {
                exitState();
            } catch (RuntimeException e) {
                cleanUpAndQuit(e);
            }
        }

        private void cleanUpAndQuit(RuntimeException e) {
            // Clean up all SaRecords.
            closeAllSaRecords(false /*expectSaClosed*/);

            mUserCbExecutor.execute(
                    () -> {
                        mIkeSessionCallback.onError(new IkeInternalException(e));
                    });
            Log.wtf(TAG, e);
            quitNow();
        }

        protected void enterState() {
            // Do nothing. Subclasses MUST override it if they are.
        }

        protected boolean processStateMessage(Message message) {
            return NOT_HANDLED;
        }

        protected void exitState() {
            // Do nothing. Subclasses MUST override it if they are.
        }
    }

    /** Called when this StateMachine quits. */
    @Override
    protected void onQuitting() {
        // Clean up all SaRecords.
        closeAllSaRecords(true /*expectSaClosed*/);

        synchronized (mChildCbToSessions) {
            for (ChildSessionStateMachine child : mChildCbToSessions.values()) {
                // Fire asynchronous call for Child Sessions to do cleanup and remove itself
                // from the map.
                child.killSession();
            }
        }

        if (mIkeSocket == null) return;
        mIkeSocket.releaseReference(this);
    }

    private void closeAllSaRecords(boolean expectSaClosed) {
        closeIkeSaRecord(mCurrentIkeSaRecord, expectSaClosed);
        closeIkeSaRecord(mLocalInitNewIkeSaRecord, expectSaClosed);
        closeIkeSaRecord(mRemoteInitNewIkeSaRecord, expectSaClosed);

        mCurrentIkeSaRecord = null;
        mLocalInitNewIkeSaRecord = null;
        mRemoteInitNewIkeSaRecord = null;
    }

    private void closeIkeSaRecord(IkeSaRecord ikeSaRecord, boolean expectSaClosed) {
        if (ikeSaRecord == null) return;

        removeIkeSaRecord(ikeSaRecord);
        ikeSaRecord.close();

        if (!expectSaClosed) return;

        Log.wtf(
                TAG,
                "IkeSaRecord with local SPI: "
                        + ikeSaRecord.getLocalSpi()
                        + " is not correctly closed.");
    }

    /** Initial state of IkeSessionStateMachine. */
    class Initial extends ExceptionHandler {
        @Override
        public void enterState() {
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

                mIkeSocket =
                        IkeSocket.getIkeSocket(
                                mIkeSessionOptions.getUdpEncapsulationSocket(),
                                IkeSessionStateMachine.this);
            } catch (ErrnoException | SocketException e) {
                // TODO: handle exception and close IkeSession.
            }
        }

        @Override
        public boolean processStateMessage(Message message) {
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
     * Idle represents a state when there is no ongoing IKE exchange affecting established IKE SA.
     */
    class Idle extends LocalRequestQueuer {
        @Override
        public void enterState() {
            mScheduler.readyForNextProcedure();
        }

        @Override
        public boolean processStateMessage(Message message) {
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
                        handleLocalRequest(message.what, (LocalRequest) message.obj);

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
                case CMD_LOCAL_REQUEST_CREATE_CHILD: // fallthrough
                case CMD_LOCAL_REQUEST_REKEY_CHILD: // fallthrough
                case CMD_LOCAL_REQUEST_DELETE_CHILD:
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

        if (msg.ikeHeader.isResponseMsg) mLastSentIkeResp = bytes;
    }

    // Builds and sends IKE-level error notification response on the provided IKE SA record
    @VisibleForTesting
    void buildAndSendErrorNotificationResponse(
            IkeSaRecord ikeSaRecord, int messageId, @ErrorType int errorType) {
        IkeInformationalPayload error = new IkeNotifyPayload(errorType);
        IkeMessage msg =
                buildEncryptedNotificationMessage(
                        ikeSaRecord,
                        new IkeInformationalPayload[] {error},
                        EXCHANGE_TYPE_INFORMATIONAL,
                        true /*isResponse*/,
                        messageId);

        sendEncryptedIkeMessage(ikeSaRecord, msg);
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

    private abstract class LocalRequestQueuer extends ExceptionHandler {
        /**
         * Reroutes all local requests to the scheduler
         *
         * @param requestVal The command value of the request
         * @param req The instance of the LocalRequest to be queued.
         */
        protected void handleLocalRequest(int requestVal, LocalRequest req) {
            if (req.isCancelled()) return;

            switch (requestVal) {
                case CMD_LOCAL_REQUEST_DELETE_IKE:
                    mScheduler.addRequestAtFront(req);
                    return;

                case CMD_LOCAL_REQUEST_REKEY_IKE: // Fallthrough
                case CMD_LOCAL_REQUEST_INFO:
                    mScheduler.addRequest(req);
                    return;

                case CMD_LOCAL_REQUEST_CREATE_CHILD: // Fallthrough
                case CMD_LOCAL_REQUEST_REKEY_CHILD: // Fallthrough
                case CMD_LOCAL_REQUEST_DELETE_CHILD:
                    if (!(req instanceof ChildLocalRequest)) {
                        throw new IllegalArgumentException(
                                "Local child request issued without valid ChildLocalRequest");
                    }
                    ChildLocalRequest childReq = (ChildLocalRequest) req;
                    if (childReq.procedureType != requestVal) {
                        throw new IllegalArgumentException(
                                "ChildLocalRequest procedure type was invalid");
                    }
                    mScheduler.addRequest(childReq);
                    return;

                default:
                    logw("Unknown local request passed to handleLocalRequest");
            }
        }
    }

    /**
     * Base state defines common behaviours when receiving an IKE packet.
     *
     * <p>State that represents an ongoing IKE procedure MUST extend BusyState to handle received
     * IKE packet. Idle state will defer the received packet to a BusyState to process it.
     */
    private abstract class BusyState extends LocalRequestQueuer {
        @Override
        public boolean processStateMessage(Message message) {
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

                case CMD_RETRANSMIT:
                    triggerRetransmit();
                    return HANDLED;

                default:
                    // Queue local requests, and trigger next procedure
                    if (message.what >= CMD_LOCAL_REQUEST_BASE
                            && message.what < CMD_LOCAL_REQUEST_BASE + CMD_CATEGORY_SIZE) {
                        handleLocalRequest(message.what, (LocalRequest) message.obj);
                        return HANDLED;
                    }
                    return NOT_HANDLED;
            }
        }

        /**
         * Handler for retransmission timer firing
         *
         * <p>By default, the trigger is logged and dropped. States that have a retransmitter should
         * override this function, and proxy the call to Retransmitter.retransmit()
         */
        protected void triggerRetransmit() {
            Log.wtf(
                    TAG,
                    "Retransmission trigger dropped in state: " + this.getClass().getSimpleName());
        }

        protected IkeSaRecord getIkeSaRecordForPacket(IkeHeader ikeHeader) {
            if (ikeHeader.fromIkeInitiator) {
                return mLocalSpiToIkeSaRecordMap.get(ikeHeader.ikeResponderSpi);
            } else {
                return mLocalSpiToIkeSaRecordMap.get(ikeHeader.ikeInitiatorSpi);
            }
        }

        protected void handleReceivedIkePacket(Message message) {
            // TODO: b/138411550 Notify subclasses when discarding a received packet. Receiving MUST
            // go back to Idle state in this case.

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
                    if (Arrays.equals(mLastReceivedIkeReq, ikePacketBytes)) {
                        mIkeSocket.sendIkePacket(mLastSentIkeResp, mRemoteAddress);

                        // Notify state if it is listening for retransmitted request.
                        handleRetransmittedReq();

                        // TODO:Support resetting remote rekey delete timer.
                    }
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
                            mLastReceivedIkeReq = ikePacketBytes;
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
                            if (ikeExchangeSubType == IKE_EXCHANGE_SUBTYPE_INVALID
                                    || ikeExchangeSubType == IKE_EXCHANGE_SUBTYPE_IKE_INIT
                                    || ikeExchangeSubType == IKE_EXCHANGE_SUBTYPE_IKE_AUTH) {
                                // TODO: Reply with INVALID_SYNTAX and close IKE Session.
                                throw new UnsupportedOperationException(
                                        "Cannot handle message with invalid or unexpected"
                                                + " IkeExchangeSubType: "
                                                + ikeExchangeSubType);
                            }
                            handleRequestIkeMessage(ikeMessage, ikeExchangeSubType, message);
                            break;
                        case DECODE_STATUS_PROTECTED_ERROR_MESSAGE:
                            ikeSaRecord.incrementRemoteRequestMessageId();
                            mLastReceivedIkeReq = ikePacketBytes;
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

        protected void handleRetransmittedReq() {
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
    class EncryptedRetransmitter extends Retransmitter {
        private final IkeSaRecord mIkeSaRecord;

        @VisibleForTesting
        EncryptedRetransmitter(IkeMessage msg) {
            this(mCurrentIkeSaRecord, msg);
        }

        private EncryptedRetransmitter(IkeSaRecord ikeSaRecord, IkeMessage msg) {
            super(getHandler(), msg);

            mIkeSaRecord = ikeSaRecord;

            retransmit();
        }

        @Override
        public void send(IkeMessage msg) {
            sendEncryptedIkeMessage(mIkeSaRecord, msg);
        }

        @Override
        public void handleRetransmissionFailure() {
            // Fire fatal error callbacks.

            quitNow();
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
         * <p>Note that this method will also quit the state machine.
         *
         * @param ikeMessage The received session deletion request
         */
        protected void handleDeleteSessionRequest(IkeMessage ikeMessage) {
            try {
                validateIkeDeleteReq(ikeMessage, mCurrentIkeSaRecord);
                IkeMessage resp = buildIkeDeleteResp(ikeMessage, mCurrentIkeSaRecord);

                mUserCbExecutor.execute(
                        () -> {
                            mIkeSessionCallback.onClosed();
                        });

                sendEncryptedIkeMessage(mCurrentIkeSaRecord, resp);

                removeIkeSaRecord(mCurrentIkeSaRecord);
                mCurrentIkeSaRecord.close();
                mCurrentIkeSaRecord = null;

                quitNow();
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
        protected void handleRetransmittedReq() {
            // Go back to IDLE - the received request was retransmitted
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
                case IKE_EXCHANGE_SUBTYPE_CREATE_CHILD: // Fall through
                case IKE_EXCHANGE_SUBTYPE_DELETE_CHILD: // Fall through
                case IKE_EXCHANGE_SUBTYPE_REKEY_CHILD:
                    deferMessage(
                            obtainMessage(
                                    CMD_RECEIVE_REQUEST_FOR_CHILD,
                                    ikeExchangeSubType,
                                    0 /*placeHolder*/,
                                    ikeMessage));
                    transitionTo(mChildProcedureOngoing);
                    return;
                default:
                    // TODO: Add support for generic INFORMATIONAL request
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
     *
     * <p>For a locally initiated Child procedure, this state is responsible for notifying Child
     * Session to initiate the exchange, building outbound request IkeMessage with Child Session
     * provided payload list and redirecting the inbound response to Child Session for validation.
     *
     * <p>For a remotely initiated Child procedure, this state is responsible for redirecting the
     * inbound request to Child Session(s) and building outbound response IkeMessage with Child
     * Session provided payload list. Exchange collision on a Child Session will be resolved inside
     * the Child Session.
     *
     * <p>For a remotely initiated IKE procedure, this state will only accept a Delete IKE request
     * and reject other types with TEMPORARY_FAILURE, since it causes conflict with the ongoing
     * Child procedure.
     *
     * <p>For most inbound request/response, this state will first pick out and handle IKE related
     * payloads and then send the rest of the payloads to Child Session for further validation. It
     * is the Child Session's responsibility to check required payloads (and verify the exchange
     * type) according to its procedure type. Only when receiving an inbound delete Child request,
     * as the only case where multiple Child Sessions will be affected by one IkeMessage, this state
     * will only send Delete Payload(s) to Child Session.
     */
    class ChildProcedureOngoing extends DeleteBase {
        // It is possible that mChildInLocalProcedure is also in mChildInRemoteProcedures when both
        // sides initiated exchange for the same Child Session.
        private ChildSessionStateMachine mChildInLocalProcedure;
        private Set<ChildSessionStateMachine> mChildInRemoteProcedures;

        private int mLastInboundRequestMsgId;
        private List<IkePayload> mOutboundRespPayloads;
        private Set<ChildSessionStateMachine> mAwaitingChildResponse;

        private EncryptedRetransmitter mRetransmitter;

        @Override
        public void enterState() {
            mChildInLocalProcedure = null;
            mChildInRemoteProcedures = new HashSet<>();

            mLastInboundRequestMsgId = 0;
            mOutboundRespPayloads = new LinkedList<>();
            mAwaitingChildResponse = new HashSet<>();
        }

        @Override
        public boolean processStateMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_REQUEST_FOR_CHILD:
                    // Handle remote request (and do state transition)
                    handleRequestIkeMessage(
                            (IkeMessage) message.obj,
                            message.arg1 /*ikeExchangeSubType*/,
                            null /*ReceivedIkePacket*/);
                    return HANDLED;
                case CMD_OUTBOUND_CHILD_PAYLOADS_READY:
                    ChildOutboundData outboundData = (ChildOutboundData) message.obj;
                    int exchangeType = outboundData.exchangeType;
                    List<IkePayload> outboundPayloads = outboundData.payloadList;

                    if (outboundData.isResp) {
                        handleOutboundResponse(
                                exchangeType, outboundPayloads, outboundData.childSession);
                    } else {
                        handleOutboundRequest(exchangeType, outboundPayloads);
                    }

                    return HANDLED;
                case CMD_CHILD_PROCEDURE_FINISHED:
                    ChildSessionStateMachine childSession = (ChildSessionStateMachine) message.obj;

                    if (mChildInLocalProcedure == childSession) {
                        mChildInLocalProcedure = null;
                    }
                    mChildInRemoteProcedures.remove(childSession);

                    transitionToIdleIfAllProceduresDone();
                    return HANDLED;
                case CMD_HANDLE_FIRST_CHILD_NEGOTIATION:
                    FirstChildNegotiationData childData = (FirstChildNegotiationData) message.obj;

                    mChildInLocalProcedure = getChildSession(childData.childSessionCallback);
                    if (mChildInLocalProcedure == null) {
                        Log.wtf(TAG, "First child not found.");

                        // TODO: Kill session, fire callbacks, and exit state machine.
                        return HANDLED;
                    }

                    mChildInLocalProcedure.handleFirstChildExchange(
                            childData.reqPayloads,
                            childData.respPayloads,
                            mLocalAddress,
                            mRemoteAddress,
                            getEncapSocketIfNeeded(),
                            mIkePrf,
                            mCurrentIkeSaRecord.getSkD());
                    return HANDLED;
                case CMD_EXECUTE_LOCAL_REQ:
                    executeLocalRequest((ChildLocalRequest) message.obj);
                    return HANDLED;
                default:
                    return super.processStateMessage(message);
            }
        }

        private void transitionToIdleIfAllProceduresDone() {
            if (mChildInLocalProcedure == null && mChildInRemoteProcedures.isEmpty()) {
                transitionTo(mIdle);
            }
        }

        private ChildSessionStateMachine getChildSession(IChildSessionCallback callbacks) {
            synchronized (mChildCbToSessions) {
                return mChildCbToSessions.get(callbacks);
            }
        }

        private UdpEncapsulationSocket getEncapSocketIfNeeded() {
            boolean isNatDetected = mIsLocalBehindNat || mIsRemoteBehindNat;

            return (isNatDetected ? mIkeSessionOptions.getUdpEncapsulationSocket() : null);
        }

        private void executeLocalRequest(ChildLocalRequest req) {
            mChildInLocalProcedure = getChildSession(req.childSessionCallback);
            if (mChildInLocalProcedure == null) {
                // This request has been validated to have a recognized target Child Session when
                // it was sent to IKE Session at the begginnig. Failing to find this Child Session
                // now means the Child creation has failed.
                logd(
                        "Child state machine not found for local request: "
                                + req.procedureType
                                + " Creation of Child Session may have been failed.");

                transitionToIdleIfAllProceduresDone();
                return;
            }
            switch (req.procedureType) {
                case CMD_LOCAL_REQUEST_CREATE_CHILD:
                    mChildInLocalProcedure.createChildSession(
                            mLocalAddress,
                            mRemoteAddress,
                            getEncapSocketIfNeeded(),
                            mIkePrf,
                            mCurrentIkeSaRecord.getSkD());
                    break;
                case CMD_LOCAL_REQUEST_REKEY_CHILD:
                    mChildInLocalProcedure.rekeyChildSession();
                    break;
                case CMD_LOCAL_REQUEST_DELETE_CHILD:
                    mChildInLocalProcedure.deleteChildSession();
                    break;
                default:
                    Log.wtf(TAG, "Invalid Child procedure type: " + req.procedureType);
                    transitionToIdleIfAllProceduresDone();
                    break;
            }
        }

        /**
         * This method is called when this state receives an inbound request or when mReceiving
         * received an inbound Child request and deferred it to this state.
         */
        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            // TODO: Grab a remote lock and hand payloads to the Child Session

            mLastInboundRequestMsgId = ikeMessage.ikeHeader.messageId;
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_CREATE_CHILD:
                    buildAndSendErrorNotificationResponse(
                            mCurrentIkeSaRecord,
                            ikeMessage.ikeHeader.messageId,
                            ERROR_TYPE_NO_ADDITIONAL_SAS);
                    break;
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    // Send response and quit state machine
                    handleDeleteSessionRequest(ikeMessage);

                    // Return immediately to avoid transitioning to mIdle
                    return;
                case IKE_EXCHANGE_SUBTYPE_DELETE_CHILD:
                    handleInboundDeleteChildRequest(ikeMessage);
                    break;
                case IKE_EXCHANGE_SUBTYPE_REKEY_IKE:
                    buildAndSendErrorNotificationResponse(
                            mCurrentIkeSaRecord,
                            ikeMessage.ikeHeader.messageId,
                            ERROR_TYPE_TEMPORARY_FAILURE);
                    break;
                case IKE_EXCHANGE_SUBTYPE_REKEY_CHILD:
                    handleInboundRekeyChildRequest(ikeMessage);
                    break;
                case IKE_EXCHANGE_SUBTYPE_GENERIC_INFO:
                    // TODO: Handle general informational request
                default:
                    throw new IllegalArgumentException(
                            "Invalid IKE exchange subtype: " + ikeExchangeSubType);
            }
            transitionToIdleIfAllProceduresDone();
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            mRetransmitter.stopRetransmitting();

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

        private void handleInboundDeleteChildRequest(IkeMessage ikeMessage) {
            // It is guaranteed in #getIkeExchangeSubType that at least one Delete Child Payload
            // exists.

            HashMap<ChildSessionStateMachine, List<IkePayload>> childToDelPayloadsMap =
                    new HashMap<>();
            Set<Integer> spiHandled = new HashSet<>();

            for (IkePayload payload : ikeMessage.ikePayloadList) {
                switch (payload.payloadType) {
                    case PAYLOAD_TYPE_VENDOR:
                        // TODO: Investigate if Vendor ID Payload can be in an INFORMATIONAL
                        // message.
                        break;
                    case PAYLOAD_TYPE_NOTIFY:
                        logw(
                                "Unexpected or unknown notification: "
                                        + ((IkeNotifyPayload) payload).notifyType);
                        break;
                    case PAYLOAD_TYPE_DELETE:
                        IkeDeletePayload delPayload = (IkeDeletePayload) payload;

                        for (int spi : delPayload.spisToDelete) {
                            ChildSessionStateMachine child = mRemoteSpiToChildSessionMap.get(spi);
                            if (child == null) {
                                // TODO: Investigate how other implementations handle that.
                                logw("Child SA not found with received SPI: " + spi);
                            } else if (!spiHandled.add(spi)) {
                                logw("Received repeated Child SPI: " + spi);
                            } else {
                                // Store Delete Payload with its target ChildSession
                                if (!childToDelPayloadsMap.containsKey(child)) {
                                    childToDelPayloadsMap.put(child, new LinkedList<>());
                                }
                                List<IkePayload> delPayloads = childToDelPayloadsMap.get(child);

                                // Avoid storing repeated Delete Payload
                                if (!delPayloads.contains(delPayload)) delPayloads.add(delPayload);
                            }
                        }

                        break;
                    case PAYLOAD_TYPE_CP:
                        // TODO: Handle it
                        break;
                    default:
                        logw("Unexpected payload types found: " + payload.payloadType);
                }
            }

            // TODO: If no Child SA is found, only reply with IKE related payloads or an empty
            // message.

            // Send Delete Payloads to Child Sessions
            for (ChildSessionStateMachine child : childToDelPayloadsMap.keySet()) {
                child.receiveRequest(
                        IKE_EXCHANGE_SUBTYPE_DELETE_CHILD,
                        EXCHANGE_TYPE_INFORMATIONAL,
                        childToDelPayloadsMap.get(child));
                mAwaitingChildResponse.add(child);
                mChildInRemoteProcedures.add(child);
            }
        }

        private void handleInboundRekeyChildRequest(IkeMessage ikeMessage) {
            // It is guaranteed in #getIkeExchangeSubType that at least one Notify-Rekey Child
            // Payload exists.
            List<IkePayload> handledPayloads = new LinkedList<>();
            ChildSessionStateMachine targetChild = null;
            Set<Integer> unrecognizedSpis = new HashSet<>();

            for (IkePayload payload : ikeMessage.ikePayloadList) {
                switch (payload.payloadType) {
                    case PAYLOAD_TYPE_VENDOR:
                        // TODO: Handle it.
                        handledPayloads.add(payload);
                        break;
                    case PAYLOAD_TYPE_NOTIFY:
                        IkeNotifyPayload notifyPayload = (IkeNotifyPayload) payload;
                        if (NOTIFY_TYPE_REKEY_SA != notifyPayload.notifyType) break;

                        int childSpi = notifyPayload.spi;
                        ChildSessionStateMachine child = mRemoteSpiToChildSessionMap.get(childSpi);

                        if (child == null) {
                            // Remember unrecognized SPIs and reply error notification if no
                            // recognized SPI found.
                            unrecognizedSpis.add(childSpi);
                            logw("Child SA not found with received SPI: " + childSpi);
                        } else if (targetChild == null) {
                            // Each message should have only one Notify-Rekey Payload. If there are
                            // multiple of them, we only process the first valid one and ignore
                            // others.
                            targetChild = mRemoteSpiToChildSessionMap.get(childSpi);
                        } else {
                            logw("More than one Notify-Rekey Payload found with SPI: " + childSpi);
                            handledPayloads.add(notifyPayload);
                        }
                        break;
                    case PAYLOAD_TYPE_CP:
                        // TODO: Handle IKE related configuration attributes and pass the payload to
                        // Child to further handle internal IP address attributes.
                        break;
                    default:
                        break;
                }
            }

            // Reject request with error notification.
            if (targetChild == null) {
                IkeInformationalPayload[] errorPayloads =
                        new IkeInformationalPayload[unrecognizedSpis.size()];
                int i = 0;
                for (Integer spi : unrecognizedSpis) {
                    errorPayloads[i++] =
                            new IkeNotifyPayload(
                                    IkePayload.PROTOCOL_ID_ESP,
                                    spi,
                                    ERROR_TYPE_CHILD_SA_NOT_FOUND,
                                    new byte[0]);
                }

                IkeMessage msg =
                        buildEncryptedNotificationMessage(
                                mCurrentIkeSaRecord,
                                errorPayloads,
                                EXCHANGE_TYPE_INFORMATIONAL,
                                true /*isResponse*/,
                                ikeMessage.ikeHeader.messageId);

                sendEncryptedIkeMessage(mCurrentIkeSaRecord, msg);
                transitionToIdleIfAllProceduresDone();
                return;
            }

            // Normal path
            List<IkePayload> payloads = new LinkedList<>();
            payloads.addAll(ikeMessage.ikePayloadList);
            payloads.removeAll(handledPayloads);

            mAwaitingChildResponse.add(targetChild);
            mChildInRemoteProcedures.add(targetChild);

            targetChild.receiveRequest(
                    IKE_EXCHANGE_SUBTYPE_REKEY_CHILD, ikeMessage.ikeHeader.exchangeType, payloads);
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

            mRetransmitter = new EncryptedRetransmitter(ikeMessage);
        }

        private void handleOutboundResponse(
                int exchangeType,
                List<IkePayload> outboundPayloads,
                ChildSessionStateMachine childSession) {
            // For each request IKE passed to Child, Child will send back to IKE a response. Even
            // if the Child Sesison is under simultaneous deletion, it will send back an empty
            // payload list.
            mOutboundRespPayloads.addAll(outboundPayloads);
            mAwaitingChildResponse.remove(childSession);
            if (!mAwaitingChildResponse.isEmpty()) return;

            IkeHeader ikeHeader =
                    new IkeHeader(
                            mCurrentIkeSaRecord.getInitiatorSpi(),
                            mCurrentIkeSaRecord.getResponderSpi(),
                            IkePayload.PAYLOAD_TYPE_SK,
                            exchangeType,
                            true /*isResp*/,
                            mCurrentIkeSaRecord.isLocalInit,
                            mLastInboundRequestMsgId);
            IkeMessage ikeMessage = new IkeMessage(ikeHeader, mOutboundRespPayloads);
            sendEncryptedIkeMessage(ikeMessage);
        }
    }

    /** CreateIkeLocalIkeInit represents state when IKE library initiates IKE_INIT exchange. */
    class CreateIkeLocalIkeInit extends BusyState {
        private IkeSecurityParameterIndex mLocalIkeSpiResource;
        private IkeSecurityParameterIndex mRemoteIkeSpiResource;
        private Retransmitter mRetransmitter;

        @Override
        public void enterState() {
            IkeMessage request = buildRequest();

            // Register local SPI to receive the IKE INIT response.
            mIkeSocket.registerIke(request.ikeHeader.ikeInitiatorSpi, IkeSessionStateMachine.this);

            mIkeInitRequestBytes = request.encode();
            mIkeInitNoncePayload =
                    request.getPayloadForType(IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class);
            mRetransmitter = new UnencryptedRetransmitter(request);
        }

        @Override
        protected void triggerRetransmit() {
            mRetransmitter.retransmit();
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
        public boolean processStateMessage(Message message) {
            switch (message.what) {
                case CMD_RECEIVE_IKE_PACKET:
                    handleReceivedIkePacket(message);
                    return HANDLED;

                default:
                    return super.processStateMessage(message);
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

                mCurrentIkeSaRecord =
                        IkeSaRecord.makeFirstIkeSaRecord(
                                mRetransmitter.getMessage(),
                                ikeMessage,
                                mLocalIkeSpiResource,
                                mRemoteIkeSpiResource,
                                mIkePrf,
                                mIkeIntegrity == null ? 0 : mIkeIntegrity.getKeyLength(),
                                mIkeCipher.getKeyLength(),
                                new LocalRequest(CMD_LOCAL_REQUEST_REKEY_IKE));

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
                        logw(
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
        public void exitState() {
            super.exitState();
            mRetransmitter.stopRetransmitting();
            // TODO: Store IKE_INIT request and response in mIkeSessionOptions for IKE_AUTH
        }

        private class UnencryptedRetransmitter extends Retransmitter {
            private UnencryptedRetransmitter(IkeMessage msg) {
                super(getHandler(), msg);

                retransmit();
            }

            @Override
            public void send(IkeMessage msg) {
                // Sends unencrypted
                mIkeSocket.sendIkePacket(msg.encode(), mRemoteAddress);
            }

            @Override
            public void handleRetransmissionFailure() {
                // Fire fatal error callbacks.

                quitNow();
            }
        }
    }

    /**
     * CreateIkeLocalIkeAuthBase represents the common state and functionality required to perform
     * IKE AUTH exchanges in both the EAP and non-EAP flows.
     */
    abstract class CreateIkeLocalIkeAuthBase extends BusyState {
        protected Retransmitter mRetransmitter;

        @Override
        protected void triggerRetransmit() {
            mRetransmitter.retransmit();
        }

        @Override
        protected final void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            Log.wtf(
                    TAG,
                    "State: "
                            + getCurrentState().getName()
                            + "received an unsupported request message with IKE exchange subtype: "
                            + ikeExchangeSubType);
        }

        protected IkeMessage buildIkeAuthReqMessage(List<IkePayload> payloadList) {
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

        protected void authenticatePsk(
                byte[] psk, IkeAuthPayload authPayload, IkeIdPayload respIdPayload)
                throws AuthenticationFailedException {
            if (authPayload.authMethod != IkeAuthPayload.AUTH_METHOD_PRE_SHARED_KEY) {
                throw new AuthenticationFailedException(
                        "Expected the remote/server to use PSK-based authentication but"
                                + " they used: "
                                + authPayload.authMethod);
            }

            IkeAuthPskPayload pskPayload = (IkeAuthPskPayload) authPayload;
            pskPayload.verifyInboundSignature(
                    psk,
                    mIkeInitResponseBytes,
                    mCurrentIkeSaRecord.nonceInitiator,
                    respIdPayload.getEncodedPayloadBody(),
                    mIkePrf,
                    mCurrentIkeSaRecord.getSkPr());
        }

        protected List<IkePayload> extractChildPayloadsFromMessage(IkeMessage ikeMessage)
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

        protected void performFirstChildNegotiation(
                List<IkePayload> childReqList, List<IkePayload> childRespList) {
            childReqList.add(mIkeInitNoncePayload);
            childRespList.add(mIkeRespNoncePayload);

            deferMessage(
                    obtainMessage(
                            CMD_HANDLE_FIRST_CHILD_NEGOTIATION,
                            new FirstChildNegotiationData(
                                    mFirstChildSessionOptions,
                                    mFirstChildCallbacks,
                                    childReqList,
                                    childRespList)));

            mUserCbExecutor.execute(
                    () -> {
                        mIkeSessionCallback.onOpened();
                    });
            transitionTo(mChildProcedureOngoing);
        }
    }

    /**
     * CreateIkeLocalIkeAuth represents state when IKE library initiates IKE_AUTH exchange.
     *
     * <p>If using EAP, CreateIkeLocalIkeAuth will transition to CreateIkeLocalIkeAuthInEap state
     * after validating the IKE AUTH response.
     */
    class CreateIkeLocalIkeAuth extends CreateIkeLocalIkeAuthBase {
        private boolean mUseEap;

        @Override
        public void enterState() {
            super.enterState();
            mRetransmitter = new EncryptedRetransmitter(buildRequest());
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
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                int exchangeType = ikeMessage.ikeHeader.exchangeType;
                if (exchangeType != IkeHeader.EXCHANGE_TYPE_IKE_AUTH) {
                    throw new InvalidSyntaxException(
                            "Expected EXCHANGE_TYPE_IKE_AUTH but received: " + exchangeType);
                }

                List<IkePayload> childReqList =
                        extractChildPayloadsFromMessage(mRetransmitter.getMessage());

                if (mUseEap) {
                    validateIkeAuthRespWithEapPayload(ikeMessage);

                    // childReqList needed after EAP completed, so persist to IkeSessionStateMachine
                    // state.
                    mFirstChildReqList = childReqList;

                    IkeEapPayload ikeEapPayload =
                            ikeMessage.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_EAP, IkeEapPayload.class);

                    deferMessage(obtainMessage(CMD_EAP_START_EAP_AUTH, ikeEapPayload));
                    transitionTo(mCreateIkeLocalIkeAuthInEap);
                } else {
                    validateIkeAuthRespWithChildPayloads(ikeMessage);

                    performFirstChildNegotiation(
                            childReqList, extractChildPayloadsFromMessage(ikeMessage));
                }
            } catch (IkeProtocolException e) {
                // TODO: Handle processing errors.
                throw new UnsupportedOperationException("Do not support handling error.", e);
            }
        }

        private IkeMessage buildIkeAuthReq() throws ResourceUnavailableException {
            List<IkePayload> payloadList = new LinkedList<>();

            // Build Identification payloads
            mInitIdPayload =
                    new IkeIdPayload(
                            true /*isInitiator*/, mIkeSessionOptions.getLocalIdentification());
            IkeIdPayload respIdPayload =
                    new IkeIdPayload(
                            false /*isInitiator*/, mIkeSessionOptions.getRemoteIdentification());
            payloadList.add(mInitIdPayload);
            payloadList.add(respIdPayload);

            // Build Authentication payload
            IkeAuthConfig authConfig = mIkeSessionOptions.getLocalAuthConfig();
            switch (authConfig.mAuthMethod) {
                case IkeSessionOptions.IKE_AUTH_METHOD_PSK:
                    IkeAuthPskPayload pskPayload =
                            new IkeAuthPskPayload(
                                    ((IkeAuthPskConfig) authConfig).mPsk,
                                    mIkeInitRequestBytes,
                                    mCurrentIkeSaRecord.nonceResponder,
                                    mInitIdPayload.getEncodedPayloadBody(),
                                    mIkePrf,
                                    mCurrentIkeSaRecord.getSkPi());
                    payloadList.add(pskPayload);
                    break;
                case IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE:
                    // TODO: Support authentication based on public key signature.
                    throw new UnsupportedOperationException(
                            "Do not support public-key based authentication.");
                case IkeSessionOptions.IKE_AUTH_METHOD_EAP:
                    // Do not include AUTH payload when using EAP.
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Unrecognized authentication method: " + authConfig.mAuthMethod);
            }

            payloadList.addAll(
                    CreateChildSaHelper.getInitChildCreateReqPayloads(
                            mIpSecManager,
                            mLocalAddress,
                            mFirstChildSessionOptions,
                            true /*isFirstChild*/));

            return buildIkeAuthReqMessage(payloadList);
        }

        private void validateIkeAuthRespWithEapPayload(IkeMessage respMsg)
                throws IkeProtocolException {
            IkeEapPayload ikeEapPayload =
                    respMsg.getPayloadForType(IkePayload.PAYLOAD_TYPE_EAP, IkeEapPayload.class);
            if (ikeEapPayload == null) {
                throw new AuthenticationFailedException("Missing EAP payload");
            }

            // TODO: check that we don't receive any ChildSaRespPayloads here

            List<IkePayload> nonEapPayloads = new LinkedList<>();
            nonEapPayloads.addAll(respMsg.ikePayloadList);
            nonEapPayloads.remove(ikeEapPayload);
            validateIkeAuthResp(nonEapPayloads);
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
            IkeAuthPayload authPayload = null;
            List<IkeCertPayload> certPayloads = new LinkedList<>();

            for (IkePayload payload : payloadList) {
                switch (payload.payloadType) {
                    case IkePayload.PAYLOAD_TYPE_ID_RESPONDER:
                        mRespIdPayload = (IkeIdPayload) payload;
                        if (!mIkeSessionOptions
                                .getRemoteIdentification()
                                .equals(mRespIdPayload.ikeId)) {
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
                        logw(
                                "Received unexpected payload in IKE AUTH response. Payload"
                                        + " type: "
                                        + payload.payloadType);
                }
            }

            // Verify existence of payloads
            if (mRespIdPayload == null || authPayload == null) {
                throw new AuthenticationFailedException("ID-Responder or Auth payload is missing.");
            }

            // Authenticate the remote peer.
            authenticate(authPayload, mRespIdPayload, certPayloads);
        }

        private void authenticate(
                IkeAuthPayload authPayload,
                IkeIdPayload respIdPayload,
                List<IkeCertPayload> certPayloads)
                throws AuthenticationFailedException {
            switch (mIkeSessionOptions.getRemoteAuthConfig().mAuthMethod) {
                case IkeSessionOptions.IKE_AUTH_METHOD_PSK:
                    authenticatePsk(
                            ((IkeAuthPskConfig) mIkeSessionOptions.getRemoteAuthConfig()).mPsk,
                            authPayload,
                            respIdPayload);
                    break;
                case IkeSessionOptions.IKE_AUTH_METHOD_PUB_KEY_SIGNATURE:
                    // STOPSHIP: b/122685769 Validate received certificates and digital signature.
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Unrecognized auth method: " + authPayload.authMethod);
            }
        }

        @Override
        public void exitState() {
            mRetransmitter.stopRetransmitting();
        }
    }

    /**
     * CreateIkeLocalIkeAuthInEap represents the state when the IKE library authenticates the client
     * with an EAP session.
     */
    class CreateIkeLocalIkeAuthInEap extends CreateIkeLocalIkeAuthBase {
        private EapAuthenticator mEapAuthenticator;

        @Override
        public void enterState() {
            IkeSessionOptions.IkeAuthEapConfig ikeAuthEapConfig =
                    (IkeSessionOptions.IkeAuthEapConfig) mIkeSessionOptions.getLocalAuthConfig();

            mEapAuthenticator =
                    mEapAuthenticatorFactory.newEapAuthenticator(
                            getHandler().getLooper(),
                            new IkeEapCallback(),
                            mContext,
                            ikeAuthEapConfig.mEapConfig);
        }

        @Override
        public boolean processStateMessage(Message msg) {
            switch (msg.what) {
                case CMD_EAP_START_EAP_AUTH:
                    IkeEapPayload ikeEapPayload = (IkeEapPayload) msg.obj;
                    mEapAuthenticator.processEapMessage(ikeEapPayload.eapMessage);

                    return HANDLED;
                case CMD_EAP_OUTBOUND_MSG_READY:
                    byte[] eapMsgBytes = (byte[]) msg.obj;
                    IkeEapPayload eapPayload = new IkeEapPayload(eapMsgBytes);

                    // Setup new retransmitter with EAP response
                    mRetransmitter =
                            new EncryptedRetransmitter(
                                    buildIkeAuthReqMessage(Arrays.asList(eapPayload)));

                    return HANDLED;
                case CMD_EAP_ERRORED:
                    handleAuthenticationFailureAndShutdown(
                            new AuthenticationFailedException((Throwable) msg.obj));
                    return HANDLED;
                case CMD_EAP_FAILED:
                    AuthenticationFailedException exception =
                            new AuthenticationFailedException("EAP Authentication Failed");

                    handleAuthenticationFailureAndShutdown(exception);
                    return HANDLED;
                case CMD_EAP_FINISH_EAP_AUTH:
                    deferMessage(msg);
                    transitionTo(mCreateIkeLocalIkeAuthPostEap);

                    return HANDLED;
                default:
                    return super.processStateMessage(msg);
            }
        }

        private void handleAuthenticationFailureAndShutdown(AuthenticationFailedException cause) {
            mUserCbExecutor.execute(
                    () -> {
                        mIkeSessionCallback.onError(cause);
                    });

            removeIkeSaRecord(mCurrentIkeSaRecord);
            mCurrentIkeSaRecord.close();
            mCurrentIkeSaRecord = null;

            quitNow();
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            mRetransmitter.stopRetransmitting();

            int exchangeType = ikeMessage.ikeHeader.exchangeType;
            if (exchangeType != IkeHeader.EXCHANGE_TYPE_IKE_AUTH) {
                // Invalid, but authenticated response.

                // TODO: Clear state and exit
                return;
            }

            IkeEapPayload eapPayload = null;
            for (IkePayload payload : ikeMessage.ikePayloadList) {
                switch (payload.payloadType) {
                    case IkePayload.PAYLOAD_TYPE_EAP:
                        eapPayload = (IkeEapPayload) payload;
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
                        break;
                    default:
                        logw(
                                "Received unexpected payload in IKE AUTH response. Payload"
                                        + " type: "
                                        + payload.payloadType);
                }
            }

            if (eapPayload == null) {
                // TODO: Handle missing EAP payload
            }

            mEapAuthenticator.processEapMessage(eapPayload.eapMessage);
        }

        private class IkeEapCallback implements IEapCallback {
            @Override
            public void onSuccess(byte[] msk, byte[] emsk) {
                // Extended MSK not used in IKEv2, drop.
                sendMessage(CMD_EAP_FINISH_EAP_AUTH, msk);
            }

            @Override
            public void onFail() {
                sendMessage(CMD_EAP_FAILED);
            }

            @Override
            public void onResponse(byte[] eapMsg) {
                sendMessage(CMD_EAP_OUTBOUND_MSG_READY, eapMsg);
            }

            @Override
            public void onError(Throwable cause) {
                sendMessage(CMD_EAP_ERRORED, cause);
            }
        }
    }

    /**
     * CreateIkeLocalIkeAuthPostEap represents the state when the IKE library is performing the
     * post-EAP PSK-base authentication run.
     */
    class CreateIkeLocalIkeAuthPostEap extends CreateIkeLocalIkeAuthBase {
        private byte[] mEapMsk = new byte[0];

        @Override
        public boolean processStateMessage(Message msg) {
            switch (msg.what) {
                case CMD_EAP_FINISH_EAP_AUTH:
                    mEapMsk = (byte[]) msg.obj;

                    IkeAuthPskPayload pskPayload =
                            new IkeAuthPskPayload(
                                    mEapMsk,
                                    mIkeInitRequestBytes,
                                    mCurrentIkeSaRecord.nonceResponder,
                                    mInitIdPayload.getEncodedPayloadBody(),
                                    mIkePrf,
                                    mCurrentIkeSaRecord.getSkPi());
                    IkeMessage postEapAuthMsg = buildIkeAuthReqMessage(Arrays.asList(pskPayload));
                    mRetransmitter = new EncryptedRetransmitter(postEapAuthMsg);

                    return HANDLED;
                default:
                    return super.processStateMessage(msg);
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                int exchangeType = ikeMessage.ikeHeader.exchangeType;
                if (exchangeType != IkeHeader.EXCHANGE_TYPE_IKE_AUTH) {
                    throw new InvalidSyntaxException(
                            "Expected EXCHANGE_TYPE_IKE_AUTH but received: " + exchangeType);
                }

                // Extract and validate existence of payloads for first Child SA setup.
                List<IkePayload> childSaRespPayloads = extractChildPayloadsFromMessage(ikeMessage);

                List<IkePayload> nonChildPayloads = new LinkedList<>();
                nonChildPayloads.addAll(ikeMessage.ikePayloadList);
                nonChildPayloads.removeAll(childSaRespPayloads);

                validateIkeAuthRespPostEap(nonChildPayloads);

                performFirstChildNegotiation(mFirstChildReqList, childSaRespPayloads);
            } catch (IkeProtocolException e) {
                // TODO: Handle processing errors.
                throw new UnsupportedOperationException("Do not support handling error.", e);
            }
        }

        private void validateIkeAuthRespPostEap(List<IkePayload> payloadList)
                throws IkeProtocolException {
            IkeAuthPayload authPayload = null;

            for (IkePayload payload : payloadList) {
                switch (payload.payloadType) {
                    case IkePayload.PAYLOAD_TYPE_AUTH:
                        authPayload = (IkeAuthPayload) payload;
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
                        break;
                    default:
                        logw(
                                "Received unexpected payload in IKE AUTH response. Payload"
                                        + " type: "
                                        + payload.payloadType);
                }
            }

            // Verify existence of payloads
            if (authPayload == null) {
                throw new AuthenticationFailedException("Post-EAP Auth payload missing.");
            }

            authenticatePsk(mEapMsk, authPayload, mRespIdPayload);
        }

        @Override
        public void exitState() {
            mRetransmitter.stopRetransmitting();
        }
    }

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
                        logw(
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
                    logw("Error notifications invalid in request: " + notifyPayload.notifyType);
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
                            isLocalInit,
                            new LocalRequest(CMD_LOCAL_REQUEST_REKEY_IKE));

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
        public void enterState() {
            try {
                mRetransmitter = new EncryptedRetransmitter(buildIkeRekeyReq());
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
                    buildAndSendErrorNotificationResponse(
                            mCurrentIkeSaRecord,
                            ikeMessage.ikeHeader.messageId,
                            ERROR_TYPE_TEMPORARY_FAILURE);
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
        public void enterState() {
            mRetransmitter = new EncryptedRetransmitter(null);
            // TODO: Populate super.mRetransmitter from state initialization data
            // Do not send request.
        }

        public IkeMessage buildRequest() {
            throw new UnsupportedOperationException(
                    "Do not support sending request in " + getCurrentState().getName());
        }

        @Override
        public void exitState() {
            // Do nothing.
        }

        @Override
        public boolean processStateMessage(Message message) {
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
                    return super.processStateMessage(message);
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
        public boolean processStateMessage(Message message) {
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
                    return super.processStateMessage(message);
                    // TODO: Add more cases for other packet types.
            }
        }

        // Rekey timer for old (and losing) SAs will be cancelled as part of the closing of the SA.
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

            synchronized (mChildCbToSessions) {
                for (ChildSessionStateMachine child : mChildCbToSessions.values()) {
                    child.setSkD(mCurrentIkeSaRecord.getSkD());
                }
            }

            // TODO: Update prf of all child sessions
        }
    }

    /**
     * SimulRekeyIkeLocalDeleteRemoteDelete represents the deleting stage during simultaneous
     * rekeying when IKE library is waiting for both a Delete request and a Delete response.
     */
    class SimulRekeyIkeLocalDeleteRemoteDelete extends RekeyIkeDeleteBase {
        private Retransmitter mRetransmitter;

        @Override
        public void enterState() {
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
            mRetransmitter =
                    new EncryptedRetransmitter(
                            mIkeSaRecordAwaitingLocalDel,
                            buildIkeDeleteReq(mIkeSaRecordAwaitingLocalDel));
            // TODO: Set timer awaiting for delete request.
        }

        @Override
        protected void triggerRetransmit() {
            mRetransmitter.retransmit();
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
        public void exitState() {
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
        public void enterState() {
            mRetransmitter = new EncryptedRetransmitter(mIkeSaRecordAwaitingLocalDel, null);
            // TODO: Populate mRetransmitter from state initialization data.
        }

        @Override
        protected void triggerRetransmit() {
            mRetransmitter.retransmit();
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            // Always return a TEMPORARY_FAILURE. In no case should we accept a message on an SA
            // that is going away. All messages on the new SA is caught in RekeyIkeDeleteBase
            buildAndSendErrorNotificationResponse(
                    mIkeSaRecordAwaitingLocalDel,
                    ikeMessage.ikeHeader.messageId,
                    ERROR_TYPE_TEMPORARY_FAILURE);
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
                    buildAndSendErrorNotificationResponse(
                            mIkeSaRecordAwaitingRemoteDel,
                            ikeMessage.ikeHeader.messageId,
                            ERROR_TYPE_TEMPORARY_FAILURE);
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
     * <p>RekeyIkeLocalDelete and SimulRekeyIkeLocalDelete have same behaviours in
     * processStateMessage(). While RekeyIkeLocalDelete overrides enterState() and exitState()
     * methods for initiating and finishing the deleting stage for IKE rekeying.
     */
    class RekeyIkeLocalDelete extends SimulRekeyIkeLocalDelete {
        private Retransmitter mRetransmitter;

        @Override
        public void enterState() {
            mIkeSaRecordSurviving = mLocalInitNewIkeSaRecord;
            mIkeSaRecordAwaitingLocalDel = mCurrentIkeSaRecord;
            mRetransmitter =
                    new EncryptedRetransmitter(
                            mIkeSaRecordAwaitingLocalDel,
                            buildIkeDeleteReq(mIkeSaRecordAwaitingLocalDel));
        }

        @Override
        protected void triggerRetransmit() {
            mRetransmitter.retransmit();
        }

        @Override
        public void exitState() {
            mRetransmitter.stopRetransmitting();
        }
    }

    /**
     * RekeyIkeRemoteDelete represents the deleting stage when responding to a Rekey procedure.
     *
     * <p>RekeyIkeRemoteDelete and SimulRekeyIkeRemoteDelete have same behaviours in
     * processStateMessage(). While RekeyIkeLocalDelete overrides enterState() and exitState()
     * methods for waiting incoming delete request and for finishing the deleting stage for IKE
     * rekeying.
     */
    class RekeyIkeRemoteDelete extends SimulRekeyIkeRemoteDelete {
        @Override
        public void enterState() {
            mIkeSaRecordSurviving = mRemoteInitNewIkeSaRecord;
            mIkeSaRecordAwaitingRemoteDel = mCurrentIkeSaRecord;

            sendMessageDelayed(TIMEOUT_REKEY_REMOTE_DELETE_IKE, REKEY_DELETE_TIMEOUT_MS);
        }

        @Override
        public boolean processStateMessage(Message message) {
            // Intercept rekey delete timeout. Assume rekey succeeded since no retransmissions
            // were received.
            if (message.what == TIMEOUT_REKEY_REMOTE_DELETE_IKE) {
                finishRekey();
                transitionTo(mIdle);

                return HANDLED;
            } else {
                return super.processStateMessage(message);
            }
        }

        @Override
        public void exitState() {
            removeMessages(TIMEOUT_REKEY_REMOTE_DELETE_IKE);
        }
    }

    /** DeleteIkeLocalDelete initiates a deletion request of the current IKE Session. */
    class DeleteIkeLocalDelete extends DeleteBase {
        private Retransmitter mRetransmitter;

        @Override
        public void enterState() {
            mRetransmitter = new EncryptedRetransmitter(buildIkeDeleteReq(mCurrentIkeSaRecord));
        }

        @Override
        protected void triggerRetransmit() {
            mRetransmitter.retransmit();
        }

        @Override
        protected void handleRequestIkeMessage(
                IkeMessage ikeMessage, int ikeExchangeSubType, Message message) {
            switch (ikeExchangeSubType) {
                case IKE_EXCHANGE_SUBTYPE_DELETE_IKE:
                    handleDeleteSessionRequest(ikeMessage);
                    return;
                default:
                    buildAndSendErrorNotificationResponse(
                            mCurrentIkeSaRecord,
                            ikeMessage.ikeHeader.messageId,
                            ERROR_TYPE_TEMPORARY_FAILURE);
            }
        }

        @Override
        protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
            try {
                validateIkeDeleteResp(ikeMessage, mCurrentIkeSaRecord);
            } catch (InvalidSyntaxException e) {
                Log.d(TAG, "Invalid syntax on IKE Delete response. Shutting down anyways", e);
            }

            mUserCbExecutor.execute(
                    () -> {
                        mIkeSessionCallback.onClosed();
                    });

            removeIkeSaRecord(mCurrentIkeSaRecord);
            mCurrentIkeSaRecord.close();
            mCurrentIkeSaRecord = null;

            quitNow();
        }

        @Override
        public void exitState() {
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
