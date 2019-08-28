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

import static com.android.ike.eap.EapAuthenticator.LOG;
import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CLIENT_ERROR;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_IDENTITY;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_NOTIFICATION;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_ENCR_DATA;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_FULLAUTH_ID_REQ;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_IV;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_PERMANENT_ID_REQ;

import android.content.Context;
import android.telephony.TelephonyManager;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapSessionConfig.EapAkaConfig;
import com.android.ike.eap.exceptions.simaka.EapSimAkaIdentityUnavailableException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaInvalidAttributeException;
import com.android.ike.eap.message.EapData.EapMethod;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapAkaTypeData;
import com.android.ike.eap.message.simaka.EapAkaTypeData.EapAkaTypeDataDecoder;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtIdentity;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData.DecodeResult;
import com.android.internal.annotations.VisibleForTesting;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * EapAkaMethodStateMachine represents the valid paths possible for the EAP-AKA protocol.
 *
 * <p>EAP-AKA sessions will always follow the path:
 *
 * Created --+--> Identity --+--> Challenge --> Final
 *           |               |
 *           +---------------+
 *
 * Note: If the EAP-Request/AKA-Challenge message contains an AUTN with an invalid sequence number,
 * the peer will indicate a synchronization failure to the server and a new challenge will be
 * attempted.
 *
 * Note: EAP-Request/Notification messages can be received at any point in the above state machine
 * At most one EAP-AKA/Notification message is allowed per EAP-AKA session.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4187">RFC 4187, Extensible Authentication
 * Protocol for Authentication and Key Agreement (EAP-AKA)</a>
 */
class EapAkaMethodStateMachine extends EapSimAkaMethodStateMachine {
    private static final String TAG = EapAkaMethodStateMachine.class.getSimpleName();

    private final TelephonyManager mTelephonyManager;
    private final EapAkaConfig mEapAkaConfig;
    private final EapAkaTypeDataDecoder mEapAkaTypeDataDecoder;

    EapAkaMethodStateMachine(Context context, EapAkaConfig eapAkaConfig) {
        this(
                (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE),
                eapAkaConfig,
                EapAkaTypeData.getEapAkaTypeDataDecoder());
    }

    @VisibleForTesting
    protected EapAkaMethodStateMachine(
            TelephonyManager telephonyManager,
            EapAkaConfig eapAkaConfig,
            EapAkaTypeDataDecoder eapAkaTypeDataDecoder) {
        mTelephonyManager = telephonyManager.createForSubscriptionId(eapAkaConfig.subId);
        mEapAkaConfig = eapAkaConfig;
        mEapAkaTypeDataDecoder = eapAkaTypeDataDecoder;

        transitionTo(new CreatedState());
    }

    @Override
    @EapMethod
    int getEapMethod() {
        return EAP_TYPE_AKA;
    }

    protected class CreatedState extends EapMethodState {
        private final String mTAG = CreatedState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            EapResult result = handleEapSuccessFailureNotification(mTAG, message);
            if (result != null) {
                return result;
            }

            DecodeResult<EapAkaTypeData> decodeResult =
                    mEapAkaTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(
                        message.eapIdentifier,
                        EAP_TYPE_AKA,
                        decodeResult.atClientErrorCode);
            }

            EapAkaTypeData eapAkaTypeData = decodeResult.eapTypeData;
            switch (eapAkaTypeData.eapSubtype) {
                case EAP_AKA_IDENTITY:
                    return transitionAndProcess(new IdentityState(), message);
                case EAP_AKA_CHALLENGE:
                    return transitionAndProcess(new ChallengeState(), message);
                case EAP_AKA_NOTIFICATION:
                    // TODO(b/139808612): move EAP-SIM/AKA notification handling to superclass
                    throw new UnsupportedOperationException(
                            "EAP-AKA notifications not supported yet");
                default:
                    return buildClientErrorResponse(
                            message.eapIdentifier,
                            EAP_TYPE_AKA,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }
        }
    }

    protected class IdentityState extends EapMethodState {
        private final String mTAG = IdentityState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            EapResult result = handleEapSuccessFailureNotification(mTAG, message);
            if (result != null) {
                return result;
            }

            DecodeResult<EapAkaTypeData> decodeResult =
                    mEapAkaTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(
                        message.eapIdentifier,
                        EAP_TYPE_AKA,
                        decodeResult.atClientErrorCode);
            }

            EapAkaTypeData eapAkaTypeData = decodeResult.eapTypeData;
            switch (eapAkaTypeData.eapSubtype) {
                case EAP_AKA_IDENTITY:
                    break;
                case EAP_AKA_CHALLENGE:
                    return transitionAndProcess(new ChallengeState(), message);
                case EAP_AKA_NOTIFICATION:
                    // TODO(b/139808612): move EAP-SIM/AKA notification handling to superclass
                    throw new UnsupportedOperationException(
                            "EAP-AKA notifications not supported yet");
                default:
                    return buildClientErrorResponse(
                            message.eapIdentifier,
                            EAP_TYPE_AKA,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            if (!isValidIdentityAttributes(eapAkaTypeData)) {
                return buildClientErrorResponse(
                        message.eapIdentifier,
                        EAP_TYPE_AKA,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            String imsi = mTelephonyManager.getSubscriberId();
            if (imsi == null) {
                LOG.e(mTAG, "Unable to get IMSI for subId=" + mEapAkaConfig.subId);
                return new EapError(
                        new EapSimAkaIdentityUnavailableException(
                                "IMSI for subId (" + mEapAkaConfig.subId + ") not available"));
            }
            String identity = "0" + imsi;
            AtIdentity atIdentity;
            try {
                atIdentity = AtIdentity.getAtIdentity(identity.getBytes());
            } catch (EapSimAkaInvalidAttributeException ex) {
                LOG.wtf(mTAG, "Exception thrown while making AtIdentity attribute", ex);
                return new EapError(ex);
            }

            return buildResponseMessage(
                    EAP_TYPE_AKA,
                    EAP_AKA_IDENTITY,
                    message.eapIdentifier,
                    Arrays.asList(atIdentity));
        }

        private boolean isValidIdentityAttributes(EapAkaTypeData eapAkaTypeData) {
            Set<Integer> attrs = eapAkaTypeData.attributeMap.keySet();

            // exactly one ID request type required
            int idRequests = 0;
            idRequests += attrs.contains(EAP_AT_PERMANENT_ID_REQ) ? 1 : 0;
            idRequests += attrs.contains(EAP_AT_ANY_ID_REQ) ? 1 : 0;
            idRequests += attrs.contains(EAP_AT_FULLAUTH_ID_REQ) ? 1 : 0;

            if (idRequests != 1) {
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
    }

    protected class ChallengeState extends EapMethodState {
        private final String mTAG = ChallengeState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            // TODO(b/133879622): implement ChallengeState#process with EapAkaTypeData decoding
            return null;
        }
    }

    EapAkaTypeData getEapSimAkaTypeData(AtClientErrorCode clientErrorCode) {
        return new EapAkaTypeData(EAP_AKA_CLIENT_ERROR, Arrays.asList(clientErrorCode));
    }

    EapAkaTypeData getEapSimAkaTypeData(int eapSubtype, List<EapSimAkaAttribute> attributes) {
        return new EapAkaTypeData(eapSubtype, attributes);
    }
}
