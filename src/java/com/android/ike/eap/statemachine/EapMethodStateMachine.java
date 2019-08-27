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

import com.android.ike.eap.EapResult;
import com.android.ike.eap.message.EapData.EapMethod;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.utils.SimpleStateMachine;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.charset.StandardCharsets;

/**
 * EapMethodStateMachine is an abstract class representing a state machine for EAP Method
 * implementations.
 */
public abstract class EapMethodStateMachine extends SimpleStateMachine<EapMessage, EapResult> {
    /**
     * Returns the EAP Method type for this EapMethodStateMachine implementation.
     *
     * @return the IANA value for the EAP Method represented by this EapMethodStateMachine
     */
    @EapMethod
    abstract int getEapMethod();

    protected EapResult handleEapNotification(String tag, EapMessage message) {
        // Type-Data will be UTF-8 encoded ISO 10646 characters (RFC 3748 Section 5.2)
        String content = new String(message.eapData.eapTypeData, StandardCharsets.UTF_8);
        LOG.i(tag, "Received EAP-Request/Notification: [" + content + "]");
        return EapMessage.getNotificationResponse(message.eapIdentifier);
    }

    @VisibleForTesting
    protected SimpleState getState() {
        return mState;
    }

    @VisibleForTesting
    protected void transitionTo(EapState newState) {
        LOG.d(
                this.getClass().getSimpleName(),
                "Transitioning from " + mState.getClass().getSimpleName()
                        + " to " + newState.getClass().getSimpleName());
        super.transitionTo(newState);
    }

    protected abstract class EapState extends SimpleState {
    }
}
