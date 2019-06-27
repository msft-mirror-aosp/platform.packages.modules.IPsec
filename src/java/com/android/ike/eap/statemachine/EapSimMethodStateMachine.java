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
import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_CLIENT_ERROR_CODE;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ENCR_DATA;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_FULLAUTH_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_IV;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_VERSION_LIST;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_CHALLENGE;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_CLIENT_ERROR;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_NOTIFICATION;
import static com.android.ike.eap.message.EapSimTypeData.EAP_SIM_START;

import android.content.Context;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtClientErrorCode;
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
import java.util.LinkedHashMap;
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
    public EapSimMethodStateMachine(Context context, EapSimTypeDataDecoder eapSimTypeDataDecoder) {
        this.mTelephonyManager = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
        this.mEapSimTypeDataDecoder = eapSimTypeDataDecoder;
        transitionTo(new CreatedState());
    }

    @VisibleForTesting
    protected SimpleState getState() {
        return mState;
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
                    return transitionAndProcess(new ChallengeState(), message);
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
            List<Integer> availableVersions = atVersionList.versions;
            if (!availableVersions.contains(AtSelectedVersion.SUPPORTED_VERSION)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNSUPPORTED_VERSION);
            }
            responseAttributes.add(AtSelectedVersion.getSelectedVersion());

            addIdentityAttributeToResponse(eapSimTypeData, responseAttributes);

            return buildResponseMessage(EAP_SIM_START, message.eapIdentifier, responseAttributes);
        }

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

        private void addIdentityAttributeToResponse(
                EapSimTypeData eapSimTypeData, List<EapSimAttribute> responseAttributes) {
            // TODO(b/135628016): implement handleIdentityRequest
        }
    }

    private class ChallengeState extends EapSimState {
        public EapResult process(EapMessage message) {
            // TODO(b/135558259): implement ChallengeState processing
            return null;
        }
    }

    private EapResult handleEapNotification(String tag, EapMessage message) {
        // Type-Data will be UTF-8 encoded ISO 10646 characters (RFC 3748 Section 5.2)
        String content = new String(message.eapData.eapTypeData, StandardCharsets.UTF_8);
        Log.i(tag, "Received EAP-Request/Notification: [" + content + "]");
        return EapMessage.getNotificationResponse(message.eapIdentifier);
    }

    private EapResult buildResponseMessage(int subtype, int identifier,
            List<EapSimAttribute> eapSimAttributes) {
        // TODO(b/135607789): implement response building here
        return null;
    }

    @VisibleForTesting
    EapResult buildClientErrorResponse(int identifier, AtClientErrorCode clientErrorCode) {
        LinkedHashMap<Integer, EapSimAttribute> attributeMap = new LinkedHashMap<>();
        attributeMap.put(EAP_AT_CLIENT_ERROR_CODE, clientErrorCode);
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_CLIENT_ERROR, attributeMap);
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
