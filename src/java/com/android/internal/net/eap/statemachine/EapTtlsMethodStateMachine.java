/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.internal.net.eap.statemachine;

import static com.android.internal.net.eap.EapAuthenticator.LOG;
import static com.android.internal.net.eap.crypto.TlsSession.TLS_STATUS_CLOSED;
import static com.android.internal.net.eap.crypto.TlsSession.TLS_STATUS_FAILURE;
import static com.android.internal.net.eap.message.EapData.EAP_IDENTITY;
import static com.android.internal.net.eap.message.EapData.EAP_TYPE_TTLS;
import static com.android.internal.net.eap.message.EapMessage.EAP_CODE_RESPONSE;
import static com.android.internal.net.eap.message.ttls.EapTtlsInboundFragmentationHelper.FRAGMENTATION_STATUS_ACK;
import static com.android.internal.net.eap.message.ttls.EapTtlsInboundFragmentationHelper.FRAGMENTATION_STATUS_ASSEMBLED;
import static com.android.internal.net.eap.message.ttls.EapTtlsInboundFragmentationHelper.FRAGMENTATION_STATUS_INVALID;

import android.annotation.Nullable;
import android.content.Context;
import android.net.eap.EapSessionConfig;
import android.net.eap.EapSessionConfig.EapTtlsConfig;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.net.eap.EapResult;
import com.android.internal.net.eap.EapResult.EapError;
import com.android.internal.net.eap.EapResult.EapResponse;
import com.android.internal.net.eap.crypto.TlsSession;
import com.android.internal.net.eap.crypto.TlsSession.TlsResult;
import com.android.internal.net.eap.crypto.TlsSessionFactory;
import com.android.internal.net.eap.exceptions.EapInvalidRequestException;
import com.android.internal.net.eap.exceptions.EapSilentException;
import com.android.internal.net.eap.exceptions.ttls.EapTtlsHandshakeException;
import com.android.internal.net.eap.exceptions.ttls.EapTtlsParsingException;
import com.android.internal.net.eap.message.EapData;
import com.android.internal.net.eap.message.EapData.EapMethod;
import com.android.internal.net.eap.message.EapMessage;
import com.android.internal.net.eap.message.ttls.EapTtlsAvp;
import com.android.internal.net.eap.message.ttls.EapTtlsInboundFragmentationHelper;
import com.android.internal.net.eap.message.ttls.EapTtlsOutboundFragmentationHelper;
import com.android.internal.net.eap.message.ttls.EapTtlsOutboundFragmentationHelper.FragmentationResult;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData.EapTtlsAcknowledgement;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData.EapTtlsTypeDataDecoder;
import com.android.internal.net.eap.message.ttls.EapTtlsTypeData.EapTtlsTypeDataDecoder.DecodeResult;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * EapTtlsMethodStateMachine represents the valid paths possible for the EAP-TTLS protocol
 *
 * <p>EAP-TTLS sessions will always follow the path:
 *
 * <p>Created --+--> Handshake --+--> Tunnel (EAP) --+--> Final
 *
 * <p>Note: EAP-TTLS will only be allowed to run once. The inner EAP instance will not be able to
 * select EAP-TTLS. This is handled in the tunnel state when a new EAP session config is created.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5281">RFC 5281, Extensible Authentication Protocol
 *     Tunneled Transport Layer Security Authenticated Protocol Version 0 (EAP-TTLSv0)</a>
 */
public class EapTtlsMethodStateMachine extends EapMethodStateMachine {

    private final Context mContext;
    private final EapSessionConfig mEapSessionConfig;
    private final EapTtlsConfig mEapTtlsConfig;
    private final EapTtlsTypeDataDecoder mTypeDataDecoder;
    private final SecureRandom mSecureRandom;
    private final TlsSessionFactory mTlsSessionFactory;

    @VisibleForTesting final EapTtlsInboundFragmentationHelper mInboundFragmentationHelper;
    @VisibleForTesting final EapTtlsOutboundFragmentationHelper mOutboundFragmentationHelper;
    @VisibleForTesting TlsSession mTlsSession;

    public EapTtlsMethodStateMachine(
            Context context,
            EapSessionConfig eapSessionConfig,
            EapTtlsConfig eapTtlsConfig,
            SecureRandom secureRandom) {
        this(
                context,
                eapSessionConfig,
                eapTtlsConfig,
                secureRandom,
                new EapTtlsTypeDataDecoder(),
                new TlsSessionFactory(),
                new EapTtlsInboundFragmentationHelper(),
                new EapTtlsOutboundFragmentationHelper());
    }

    @VisibleForTesting
    public EapTtlsMethodStateMachine(
            Context context,
            EapSessionConfig eapSessionConfig,
            EapTtlsConfig eapTtlsConfig,
            SecureRandom secureRandom,
            EapTtlsTypeDataDecoder typeDataDecoder,
            TlsSessionFactory tlsSessionFactory,
            EapTtlsInboundFragmentationHelper inboundFragmentationHelper,
            EapTtlsOutboundFragmentationHelper outboundFragmentationHelper) {
        mContext = context;
        mEapSessionConfig = eapSessionConfig;
        mEapTtlsConfig = eapTtlsConfig;
        mTypeDataDecoder = typeDataDecoder;
        mSecureRandom = secureRandom;
        mTlsSessionFactory = tlsSessionFactory;
        mInboundFragmentationHelper = inboundFragmentationHelper;
        mOutboundFragmentationHelper = outboundFragmentationHelper;

        transitionTo(new CreatedState());
    }

    @Override
    @EapMethod
    int getEapMethod() {
        return EAP_TYPE_TTLS;
    }

    @Override
    EapResult handleEapNotification(String tag, EapMessage message) {
        return EapStateMachine.handleNotification(tag, message);
    }

    /**
     * The created state verifies the start request before transitioning to phase 1 of EAP-TTLS
     * (RFC5281#7.1)
     */
    protected class CreatedState extends EapMethodState {
        private final String mTAG = this.getClass().getSimpleName();

        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/160781895): Support decoding AVP's pre-tunnel in EAP-TTLS
            EapResult result = handleEapSuccessFailureNotification(mTAG, message);
            if (result != null) {
                return result;
            }

            DecodeResult decodeResult =
                    mTypeDataDecoder.decodeEapTtlsRequestPacket(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                LOG.e(mTAG, "Error parsing EAP-TTLS packet type data", decodeResult.eapError.cause);
                return decodeResult.eapError;
            } else if (!decodeResult.eapTypeData.isStart) {
                return new EapError(
                        new EapInvalidRequestException(
                                "Unexpected request received in EAP-TTLS: Received first request"
                                        + " without start bit set."));
            }

            return transitionAndProcess(new HandshakeState(), message);
        }
    }

    /**
     * The handshake (phase 1) state builds the tunnel for tunneled EAP authentication in phase 2
     *
     * <p>As per RFC5281#9.2.1, version negotiation occurs during the first exchange between client
     * and server. In other words, this is an implicit negotiation and is not handled independently.
     * In this case, the version will always be zero because that is the only currently supported
     * version of EAP-TTLS at the time of writing. The initiation of the handshake (RFC5281#7.1) is
     * the first response sent by the client.
     */
    protected class HandshakeState extends EapMethodState {
        private final String mTAG = this.getClass().getSimpleName();

        private static final int DEFAULT_VENDOR_ID = 0;

        @Override
        public EapResult process(EapMessage message) {
            EapResult eapResult = handleEapSuccessFailureNotification(mTAG, message);
            if (eapResult != null) {
                return eapResult;
            }

            DecodeResult decodeResult =
                    mTypeDataDecoder.decodeEapTtlsRequestPacket(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                LOG.e(mTAG, "Error parsing EAP-TTLS packet type data", decodeResult.eapError.cause);
                if (mTlsSession == null) {
                    return decodeResult.eapError;
                }
                return transitionToAwaitingClosureState(
                        mTAG, message.eapIdentifier, decodeResult.eapError);
            }

            EapTtlsTypeData eapTtlsRequest = decodeResult.eapTypeData;

            // If the remote is in the midst of sending a fragmented message, ack the fragment and
            // return
            EapResult inboundFragmentAck =
                    handleInboundFragmentation(mTAG, eapTtlsRequest, message.eapIdentifier);
            if (inboundFragmentAck != null) {
                return inboundFragmentAck;
            }

            if (eapTtlsRequest.isStart) {
                if (mTlsSession != null) {
                    return transitionToAwaitingClosureState(
                            mTAG,
                            message.eapIdentifier,
                            new EapError(
                                    new EapInvalidRequestException(
                                            "Received a start request when a session is already in"
                                                    + " progress")));
                }

                return startHandshake(message.eapIdentifier);
            }

            EapResult nextOutboundFragment =
                    getNextOutboundFragment(mTAG, eapTtlsRequest, message.eapIdentifier);
            if (nextOutboundFragment != null) {
                // Skip further processing, send remaining outbound fragments
                return nextOutboundFragment;
            }

            // TODO(b/159929700): Implement handshake (phase 1) of EAP-TTLS
            return null;
        }

        /**
         * Initializes the TlsSession and starts a TLS handshake
         *
         * @param eapIdentifier the eap identifier for the response
         * @return an EAP response containing the ClientHello message, or an EAP error if the TLS
         *     handshake fails to begin
         */
        private EapResult startHandshake(int eapIdentifier) {
            try {
                mTlsSession =
                        mTlsSessionFactory.newInstance(
                                mEapTtlsConfig.getTrustedCa(), mSecureRandom);
            } catch (GeneralSecurityException | IOException e) {
                return new EapError(
                        new EapTtlsHandshakeException(
                                "There was an error creating the TLS Session.", e));
            }

            TlsResult tlsResult = mTlsSession.startHandshake();
            if (tlsResult.status == TLS_STATUS_FAILURE) {
                return new EapError(new EapTtlsHandshakeException("Failed to start handshake."));
            }

            return buildEapMessageResponse(mTAG, eapIdentifier, tlsResult.data);
        }

        /**
         * Builds an EAP-MESSAGE AVP containing an EAP-Identity response
         *
         * <p>Note that this uses the EAP-Identity in the session config nested within EapTtlsConfig
         * which may be different than the identity in the top-level EapSessionConfig
         *
         * @param eapIdentifier the eap identifier for the response
         * @throws EapSilentException if an error occurs creating the eap message
         */
        @VisibleForTesting
        byte[] buildEapIdentityResponseAvp(int eapIdentifier) throws EapSilentException {
            EapData eapData =
                    new EapData(
                            EAP_IDENTITY, mEapTtlsConfig.getInnerEapSessionConfig().eapIdentity);
            EapMessage eapMessage = new EapMessage(EAP_CODE_RESPONSE, eapIdentifier, eapData);
            return EapTtlsAvp.getEapMessageAvp(DEFAULT_VENDOR_ID, eapMessage.encode()).encode();
        }
    }

    /**
     * The tunnel state (phase 2) tunnels data produced by an inner EAP instance
     *
     * <p>The tunnel state creates an inner EAP instance via a new EAP state machine and handles
     * decryption and encryption of data using the previously established TLS tunnel (RFC5281#7.2)
     */
    protected class TunnelState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/159926139): Implement tunnel state (phase 2) of EAP-TTLS (RFC5281#7.2)
            return null;
        }
    }

    /**
     * The closure state handles closure of the TLS session in EAP-TTLS
     *
     * <p>Note that this state is only entered following an error. If EAP authentication
     * completes successfully or fails, the tunnel is assumed to have implicitly closed.
     */
    protected class AwaitingClosureState extends EapMethodState {
        private final String mTAG = this.getClass().getSimpleName();

        private final EapError mEapError;

        /**
         * Initializes the closure state
         *
         * <p>The awaiting closure state is an error state. If a server responds to a close-notify,
         * the data is processed and the EAP error which encapsulates the initial error is returned
         *
         * @param eapError an EAP error that contains the error that initially caused a close to
         *     occur
         */
        public AwaitingClosureState(EapError eapError) {
            mEapError = eapError;
        }

        @Override
        public EapResult process(EapMessage message) {
            EapResult result = handleEapSuccessFailureNotification(mTAG, message);
            if (result != null) {
                return result;
            }

            DecodeResult decodeResult =
                    mTypeDataDecoder.decodeEapTtlsRequestPacket(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                LOG.e(mTAG, "Error parsing EAP-TTLS packet type data", decodeResult.eapError.cause);
                return decodeResult.eapError;
            }

            // if the server sent data, we process it and return an EapError.
            // A response is not required and is additionally unlikely as we have already sent the
            // closure-notify
            mTlsSession.processIncomingData(decodeResult.eapTypeData.data);

            return mEapError;
        }
    }

    /**
     * Transitions to the awaiting closure state and attempts to close the TLS tunnel
     *
     * @param tag the tag of the calling class
     * @param eapIdentifier the EAP identifier from the most recent EAP request
     * @param eapError the EAP error to return if closure fails
     * @return a closure notify TLS message or an EAP error if one cannot be generated
     */
    @VisibleForTesting
    EapResult transitionToAwaitingClosureState(String tag, int eapIdentifier, EapError eapError) {
        TlsResult closureResult = mTlsSession.closeConnection();
        if (closureResult.status != TLS_STATUS_CLOSED) {
            LOG.e(tag, "Failed to close the TLS session");
            return eapError;
        }

        transitionTo(new AwaitingClosureState(eapError));
        return buildEapMessageResponse(
                tag,
                eapIdentifier,
                EapTtlsTypeData.getEapTtlsTypeData(
                        false /* isFragmented */,
                        false /* start */,
                        0 /* version 0 */,
                        closureResult.data.length,
                        closureResult.data));
    }

    /**
     * Verifies whether outbound fragmentation is in progress and constructs the next fragment if
     * necessary
     *
     * @param tag the tag for the calling class
     * @param eapTtlsRequest the request received from the server
     * @param eapIdentifier the eap identifier from the latest message
     * @return an eap response if the next fragment exists, or null if no fragmentation is in
     *     progress
     */
    @Nullable
    private EapResult getNextOutboundFragment(
            String tag, EapTtlsTypeData eapTtlsRequest, int eapIdentifier) {
        if (eapTtlsRequest.isAcknowledgmentPacket()) {
            if (mOutboundFragmentationHelper.hasRemainingFragments()) {
                FragmentationResult result = mOutboundFragmentationHelper.getNextOutboundFragment();
                return buildEapMessageResponse(
                        tag,
                        eapIdentifier,
                        EapTtlsTypeData.getEapTtlsTypeData(
                                result.hasRemainingFragments,
                                false /* start */,
                                0 /* version 0 */,
                                0 /* messageLength */,
                                result.fragmentedData));
            } else {
                return transitionToAwaitingClosureState(
                        tag,
                        eapIdentifier,
                        new EapError(
                                new EapInvalidRequestException(
                                        "Received an ack but no packet was in the process of"
                                                + " being fragmented.")));
            }
        } else if (mOutboundFragmentationHelper.hasRemainingFragments()) {
            return transitionToAwaitingClosureState(
                    tag,
                    eapIdentifier,
                    new EapError(
                            new EapInvalidRequestException(
                                    "Received a standard EAP-Request but was expecting an ack to a"
                                            + " fragment.")));
        }

        return null;
    }

    /**
     * Processes incoming data, and if necessary, assembles fragments
     *
     * @param tag the tag for the calling class
     * @param eapTtlsRequest the request received from the server
     * @param eapIdentifier the eap identifier from the latest message
     * @return an acknowledgment if the received data is a fragment, null if data is ready to
     *     process
     */
    @Nullable
    private EapResult handleInboundFragmentation(
            String tag, EapTtlsTypeData eapTtlsRequest, int eapIdentifier) {
        int fragmentationStatus =
                mInboundFragmentationHelper.assembleInboundMessage(eapTtlsRequest);

        switch (fragmentationStatus) {
            case FRAGMENTATION_STATUS_ASSEMBLED:
                return null;
            case FRAGMENTATION_STATUS_ACK:
                LOG.d(tag, "Packet is fragmented. Generating an acknowledgement response.");
                return buildEapMessageResponse(
                        tag, eapIdentifier, EapTtlsAcknowledgement.getEapTtlsAcknowledgement());
            case FRAGMENTATION_STATUS_INVALID:
                return transitionToAwaitingClosureState(
                        tag,
                        eapIdentifier,
                        new EapError(
                                new EapTtlsParsingException(
                                        "Fragmentation failure: There was an error decoding the"
                                                + " fragmented request.")));
            default:
                return transitionToAwaitingClosureState(
                        tag,
                        eapIdentifier,
                        new EapError(
                                new IllegalStateException(
                                        "Received an unknown fragmentation status when assembling"
                                                + " an inbound fragment: "
                                                + fragmentationStatus)));
        }
    }

    /**
     * Takes outbound data and assembles an EAP-Response.
     *
     * <p>The data will be fragmented if necessary
     *
     * @param tag the tag of the calling class
     * @param eapIdentifier the EAP identifier from the most recent EAP request
     * @param data the data used to build the EAP-TTLS type data
     * @return an EAP result that is either an EAP response or an EAP error
     */
    private EapResult buildEapMessageResponse(String tag, int eapIdentifier, byte[] data) {
        // TODO(b/165668196): Modify outbound fragmentation helper to be per-message in EAP-TTLS
        mOutboundFragmentationHelper.setupOutboundFragmentation(data);
        FragmentationResult result = mOutboundFragmentationHelper.getNextOutboundFragment();

        // As per RFC5281#9.2.2, an unfragmented packet may have the length bit set
        return buildEapMessageResponse(
                tag,
                eapIdentifier,
                EapTtlsTypeData.getEapTtlsTypeData(
                        result.hasRemainingFragments,
                        false /* start */,
                        0 /* version 0 */,
                        data.length,
                        result.fragmentedData));
    }

    /**
     * Takes an already constructed EapTtlsTypeData and builds an EAP-Response
     *
     * @param tag the tag of the calling class
     * @param eapIdentifier the EAP identifier from the most recent EAP request
     * @param eapTtlsTypeData the type data to use in the EAP Response
     * @return an EAP result that is either an EAP response or an EAP error
     */
    private EapResult buildEapMessageResponse(
            String tag, int eapIdentifier, EapTtlsTypeData eapTtlsTypeData) {
        try {
            EapData eapData = new EapData(getEapMethod(), eapTtlsTypeData.encode());
            EapMessage eapMessage = new EapMessage(EAP_CODE_RESPONSE, eapIdentifier, eapData);
            return EapResponse.getEapResponse(eapMessage);
        } catch (EapSilentException ex) {
            LOG.e(tag, "Error building response EapMessage", ex);
            return new EapError(ex);
        }
    }
}

