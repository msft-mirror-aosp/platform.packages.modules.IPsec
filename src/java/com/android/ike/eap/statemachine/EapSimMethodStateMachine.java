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

package com.android.ike.eap.statemachine;

import static com.android.ike.eap.message.EapData.EAP_NOTIFICATION;
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ENCR_DATA;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_FULLAUTH_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_IV;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_RAND;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_VERSION_LIST;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_CHALLENGE;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_CLIENT_ERROR;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_NOTIFICATION;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_START;

import android.annotation.Nullable;
import android.content.Context;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtClientErrorCode;
import com.android.ike.eap.message.EapSimAttribute.AtIdentity;
import com.android.ike.eap.message.EapSimAttribute.AtNonceMt;
import com.android.ike.eap.message.EapSimAttribute.AtSelectedVersion;
import com.android.ike.eap.message.EapSimAttribute.AtVersionList;
import com.android.ike.eap.message.EapSimTypeData;
import com.android.ike.eap.message.EapSimTypeData.EapSimTypeDataDecoder;
import com.android.ike.eap.message.EapSimTypeData.EapSimTypeDataDecoder.DecodeResult;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * EapSimMethodStateMachine represents the valid paths possible for the EAP-SIM protocol.
 *
 * <p>EAP-SIM procedures will always follow the path:
 *
 * Created ---> Start --+--> Challenge --+--> null
 *                      |                |
 *                      +-->  failed  >--+
 *
 * Note that EAP-SIM/Notification messages can be received at any point in the above state machine.
 * At most one EAP-SIM/Notification message is allowed per EAP-SIM session.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186">RFC 4186, Extensible Authentication Protocol
 * Method for Subscriber Identity Modules (EAP-SIM)</a>
 */
public class EapSimMethodStateMachine extends EapMethodStateMachine {
    private static final String TAG = "EapSimMethodStateMachine";
    private static final SecureRandom EAP_SIM_RANDOM = new SecureRandom();

    private final TelephonyManager mTelephonyManager;
    private final EapSimTypeDataDecoder mEapSimTypeDataDecoder;

    public EapSimMethodStateMachine(Context context) {
        this.mTelephonyManager = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
        this.mEapSimTypeDataDecoder = new EapSimTypeDataDecoder();
        transitionTo(new CreatedState());
    }

    @VisibleForTesting
    public EapSimMethodStateMachine(TelephonyManager telephonyManager,
            EapSimTypeDataDecoder eapSimTypeDataDecoder) {
        if (telephonyManager == null) {
            throw new IllegalArgumentException("TelephonyManager must be non-null");
        } else if (eapSimTypeDataDecoder == null) {
            throw new IllegalArgumentException("EapSimTypeDataDecoder must be non-null");
        }

        this.mTelephonyManager = telephonyManager;
        this.mEapSimTypeDataDecoder = eapSimTypeDataDecoder;
        transitionTo(new CreatedState());
    }

    @VisibleForTesting
    protected SimpleState getState() {
        return mState;
    }

    @VisibleForTesting
    protected void transitionTo(EapSimState newState) {
        super.transitionTo(newState);
    }

    protected abstract class EapSimState extends SimpleState {
        protected EapResult handleEapSimNotification(String tag, int identifier,
                EapSimTypeData eapSimTypeData) {
            // TODO(b/135625951): implement handleEapSimNotification
            return null;
        }
    }

    protected class CreatedState extends EapSimState {
        private final String mTAG = CreatedState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            if (message.eapData.eapType == EAP_NOTIFICATION) {
                return handleEapNotification(mTAG, message);
            }

            DecodeResult decodeResult = mEapSimTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(message.eapIdentifier,
                        decodeResult.atClientErrorCode);
            }

            EapSimTypeData eapSimTypeData = decodeResult.eapSimTypeData;
            switch (eapSimTypeData.eapSubtype) {
                case EAP_SIM_START:
                    break;
                case EAP_SIM_NOTIFICATION:
                    return handleEapSimNotification(mTAG, message.eapIdentifier, eapSimTypeData);
                default:
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            byte[] nonce = new byte[AtNonceMt.NONCE_MT_LENGTH];
            EAP_SIM_RANDOM.nextBytes(nonce);
            AtNonceMt atNonceMt;
            try {
                atNonceMt = new AtNonceMt(nonce);
            } catch (EapSimInvalidAttributeException ex) {
                Log.wtf(mTAG, "Exception thrown while creating AtNonceMt", ex);
                return new EapError(ex);
            }
            return transitionAndProcess(new StartState(atNonceMt), message);
        }
    }

    protected class StartState extends EapSimState {
        private final String mTAG = StartState.class.getSimpleName();
        private final AtNonceMt mAtNonceMt;

        private List<Integer> mVersions;

        protected StartState(AtNonceMt atNonceMt) {
            this.mAtNonceMt = atNonceMt;
        }

        public EapResult process(EapMessage message) {
            if (message.eapData.eapType == EAP_NOTIFICATION) {
                return handleEapNotification(mTAG, message);
            }

            DecodeResult decodeResult = mEapSimTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(message.eapIdentifier,
                        decodeResult.atClientErrorCode);
            }

            EapSimTypeData eapSimTypeData = decodeResult.eapSimTypeData;
            switch (eapSimTypeData.eapSubtype) {
                case EAP_SIM_START:
                    break;
                case EAP_SIM_NOTIFICATION:
                    return handleEapSimNotification(mTAG, message.eapIdentifier, eapSimTypeData);
                case EAP_SIM_CHALLENGE:
                    // By virtue of being in the StartState, we have received (and processed) the
                    // EAP-SIM/Start request. Receipt of an EAP-SIM/Challenge request indicates that
                    // the server has accepted our EAP-SIM/Start response, including our identity
                    // (if any).
                    return transitionAndProcess(new ChallengeState(mVersions, mAtNonceMt), message);
                default:
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            if (!isValidStartAttributes(eapSimTypeData)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            List<EapSimAttribute> responseAttributes = new ArrayList<>();
            responseAttributes.add(mAtNonceMt);

            // choose EAP-SIM version
            AtVersionList atVersionList = (AtVersionList)
                    eapSimTypeData.attributeMap.get(EAP_AT_VERSION_LIST);
            mVersions = atVersionList.versions;
            if (!mVersions.contains(AtSelectedVersion.SUPPORTED_VERSION)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNSUPPORTED_VERSION);
            }
            responseAttributes.add(AtSelectedVersion.getSelectedVersion());

            try {
                AtIdentity atIdentity = getIdentityResponse(eapSimTypeData);
                if (atIdentity != null) {
                    responseAttributes.add(atIdentity);
                }
            } catch (EapSimInvalidAttributeException ex) {
                Log.d(mTAG, "Exception thrown while making AtIdentity attribute", ex);
                return new EapError(ex);
            }

            return buildResponseMessage(EAP_SIM_START, message.eapIdentifier, responseAttributes);
        }

        /**
         * Returns true iff the given EapSimTypeData meets the following conditions:
         *  - contains an AT_VERSION_LIST attribute
         *  - contains at most one of AT_PERMANENT_ID_REQ, AT_ANY_ID_REQ, or AT_FULLAUTH_D_REQ
         *      attributes
         *  - does not contain AT_MAC, AT_IV, or AT_ENCR_DATA attributes
         */
        @VisibleForTesting
        boolean isValidStartAttributes(EapSimTypeData eapSimTypeData) {
            // must contain: version list
            Set<Integer> attrs = eapSimTypeData.attributeMap.keySet();
            if (!attrs.contains(EAP_AT_VERSION_LIST)) {
                return false;
            }

            // may contain: ID request (but only 1)
            int idRequests = 0;
            if (attrs.contains(EAP_AT_PERMANENT_ID_REQ)) {
                idRequests++;
            }
            if (attrs.contains(EAP_AT_ANY_ID_REQ)) {
                idRequests++;
            }
            if (attrs.contains(EAP_AT_FULLAUTH_ID_REQ)) {
                idRequests++;
            }
            if (idRequests > 1) {
                return false;
            }

            // can't contain mac, iv, encr data
            if (attrs.contains(EAP_AT_MAC)
                    || attrs.contains(EAP_AT_IV)
                    || attrs.contains(EAP_AT_ENCR_DATA)) {
                return false;
            }
            return true;
        }

        @VisibleForTesting
        @Nullable
        AtIdentity getIdentityResponse(EapSimTypeData eapSimTypeData)
                throws EapSimInvalidAttributeException {
            Set<Integer> attributes = eapSimTypeData.attributeMap.keySet();

            // TODO(b/136180022): process separate ID requests differently (pseudonym vs permanent)
            if (attributes.contains(EAP_AT_PERMANENT_ID_REQ)
                    || attributes.contains(EAP_AT_FULLAUTH_ID_REQ)
                    || attributes.contains(EAP_AT_ANY_ID_REQ)) {
                // TODO(b/136482803): handle case where identity unavailable
                // Permanent Identity is "1" + IMSI (RFC 4186 Section 4.1.2.6)
                String identity = "1" + mTelephonyManager.getSubscriberId();
                return AtIdentity.getAtIdentity(identity.getBytes());
            }
            return null;
        }
    }

    protected class ChallengeState extends EapSimState {
        private final String mTAG = ChallengeState.class.getSimpleName();

        // K_aut length is 16 bytes (RFC 4186 Section 7)
        private final int mKeyAutLen = 16;

        // Session Key lengths are 64 bytes (RFC 4186 Section 7)
        private final int mSessionKeyLength = 64;

        private final List<Integer> mVersions;
        private final byte[] mNonce;

        private final byte[] mKAutn = new byte[mKeyAutLen];
        @VisibleForTesting final byte[] mMsk = new byte[mSessionKeyLength];
        @VisibleForTesting final byte[] mEmsk = new byte[mSessionKeyLength];

        protected ChallengeState(List<Integer> versions, AtNonceMt atNonceMt) {
            mVersions = versions;
            mNonce = atNonceMt.nonceMt;
        }

        public EapResult process(EapMessage message) {
            if (message.eapCode == EAP_CODE_SUCCESS) {
                transitionTo(new FinalState());
                return new EapSuccess(mMsk, mEmsk);
            } else if (message.eapCode == EAP_CODE_FAILURE) {
                transitionTo(new FinalState());
                return new EapFailure();
            } else if (message.eapData.eapType == EAP_NOTIFICATION) {
                return handleEapNotification(mTAG, message);
            }

            DecodeResult decodeResult = mEapSimTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(message.eapIdentifier,
                        decodeResult.atClientErrorCode);
            }

            EapSimTypeData eapSimTypeData = decodeResult.eapSimTypeData;
            switch (eapSimTypeData.eapSubtype) {
                case EAP_SIM_NOTIFICATION:
                    return handleEapSimNotification(mTAG, message.eapIdentifier, eapSimTypeData);
                case EAP_SIM_CHALLENGE:
                    break;
                default:
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            if (!isValidChallengeAttributes(eapSimTypeData)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            // TODO(b/136279114): process RAND challenges

            // TODO(b/136280277): generate keys with FIPS 186-2

            // TODO(b/136281777): check if received MAC == MAC(packet | nonce)

            return null;
        }

        /**
         * Returns true iff the given EapSimTypeData contains both AT_RAND and AT_MAC attributes.
         */
        @VisibleForTesting
        boolean isValidChallengeAttributes(EapSimTypeData eapSimTypeData) {
            Set<Integer> attrs = eapSimTypeData.attributeMap.keySet();
            return attrs.contains(EAP_AT_RAND) && attrs.contains(EAP_AT_MAC);
        }
    }

    protected class FinalState extends EapSimState {
        @Override
        public EapResult process(EapMessage msg) {
            return new EapError(
                    new IllegalStateException("Attempting to process from a FinalState"));
        }
    }

    private EapResult handleEapNotification(String tag, EapMessage message) {
        // Type-Data will be UTF-8 encoded ISO 10646 characters (RFC 3748 Section 5.2)
        String content = new String(message.eapData.eapTypeData, StandardCharsets.UTF_8);
        Log.i(tag, "Received EAP-Request/Notification: [" + content + "]");
        return EapMessage.getNotificationResponse(message.eapIdentifier);
    }

    @VisibleForTesting
    EapResult buildResponseMessage(int subtype, int identifier,
            List<EapSimAttribute> eapSimAttributes) {
        EapSimTypeData eapSimTypeData = new EapSimTypeData(subtype, eapSimAttributes);
        EapData eapData = new EapData(EAP_TYPE_SIM, eapSimTypeData.encode());

        try {
            EapMessage eapMessage = new EapMessage(EAP_CODE_RESPONSE, identifier, eapData);
            return EapResponse.getEapResponse(eapMessage);
        } catch (EapSilentException ex) {
            Log.d(TAG, "Exception while creating EapMessage response for Client Error", ex);
            return new EapError(ex);
        }
    }

    @VisibleForTesting
    EapResult buildClientErrorResponse(int identifier, AtClientErrorCode clientErrorCode) {
        EapSimTypeData eapSimTypeData = new EapSimTypeData(
                EAP_SIM_CLIENT_ERROR, Arrays.asList(clientErrorCode));
        byte[] encodedTypeData = eapSimTypeData.encode();

        EapData eapData = new EapData(EAP_TYPE_SIM, encodedTypeData);
        try {
            EapMessage response = new EapMessage(EAP_CODE_RESPONSE, identifier, eapData);
            return EapResponse.getEapResponse(response);
        } catch (EapSilentException ex) {
            Log.d(TAG, "Exception while creating EapMessage response for Client Error", ex);
            return new EapError(ex);
        }
    }
}
