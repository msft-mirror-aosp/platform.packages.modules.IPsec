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

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CLIENT_ERROR;

import android.content.Context;
import android.telephony.TelephonyManager;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapSessionConfig.EapAkaConfig;
import com.android.ike.eap.message.EapData.EapMethod;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapAkaTypeData;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;

import java.util.Arrays;

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

    EapAkaMethodStateMachine(Context context, EapAkaConfig eapAkaConfig) {
        TelephonyManager telephonyManager =
                (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        mTelephonyManager = telephonyManager.createForSubscriptionId(eapAkaConfig.subId);
        mEapAkaConfig = eapAkaConfig;

        transitionTo(new CreatedState());
    }

    @Override
    @EapMethod
    int getEapMethod() {
        return EAP_TYPE_AKA;
    }

    protected class CreatedState extends EapState {
        private final String mTAG = CreatedState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            // TODO(b/139541513): implement CreatedState#process with EapAkaTypeData decoding
            throw new UnsupportedOperationException();
        }
    }

    protected class IdentityState extends EapState {
        private final String mTAG = IdentityState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            // TODO(b/133880036): implement IdentityState#process with EapAkaTypeData decoding
            throw new UnsupportedOperationException();
        }
    }

    protected class ChallengeState extends EapState {
        private final String mTAG = ChallengeState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            // TODO(b/133879622): implement ChallengeState#process with EapAkaTypeData decoding
            throw new UnsupportedOperationException();
        }
    }

    EapAkaTypeData getEapSimAkaTypeData(AtClientErrorCode clientErrorCode) {
        return new EapAkaTypeData(EAP_AKA_CLIENT_ERROR, Arrays.asList(clientErrorCode));
    }
}
