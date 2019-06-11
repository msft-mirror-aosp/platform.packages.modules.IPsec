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

import android.content.Context;
import android.telephony.TelephonyManager;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.message.EapMessage;
import com.android.internal.annotations.VisibleForTesting;

/**
 * EapSimMethodStateMachine represents the valid paths possible for the EAP-SIM protocol.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186">RFC 4186, Extensible Authentication Protocol
 * Method for Subscriber Identity Modules (EAP-SIM)</a>
 */
public class EapSimMethodStateMachine extends EapMethodStateMachine {
    private final TelephonyManager mTelephonyManager;

    public EapSimMethodStateMachine(Context context) {
        this.mTelephonyManager = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
        transitionTo(new CreatedState());
    }

    @VisibleForTesting
    protected SimpleState getState() {
        return mState;
    }

    protected class CreatedState extends SimpleState {
        public EapResult process(EapMessage message) {
            // TODO(134590477): decode EapMessage type data
            // TODO(134590479): implement EAP/SIM/Start message handling

            return null;
        }
    }
}
