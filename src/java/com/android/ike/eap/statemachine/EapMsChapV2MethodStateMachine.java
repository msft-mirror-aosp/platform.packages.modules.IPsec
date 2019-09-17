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

import static com.android.ike.eap.message.EapData.EAP_TYPE_MSCHAP_V2;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapSessionConfig.EapMsChapV2Config;
import com.android.ike.eap.message.EapData.EapMethod;
import com.android.ike.eap.message.EapMessage;

import java.security.SecureRandom;

/**
 * EapMsChapV2MethodStateMachine represents the valid paths possible for the EAP MSCHAPv2 protocol.
 *
 * <p>EAP MSCHAPv2 sessions will always follow the path:
 *
 * <p>CreatedState --> ChallengeState --> PostChallengeState --> FinalState
 *
 * <p>Note: All Failure-Request messages received in the PostChallenge state will be responded to
 * with Failure-Response messages. That is, retryable failures <i>will not</i> be retried.
 *
 * @see <a href="https://tools.ietf.org/html/draft-kamath-pppext-eap-mschapv2-02">Microsoft EAP CHAP
 *     Extensions Draft (EAP MSCHAPv2)</a>
 * @see <a href="https://tools.ietf.org/html/rfc2759">RFC 2759, Microsoft PPP CHAP Extensions,
 *     Version 2 (MSCHAPv2)</a>
 * @see <a href="https://tools.ietf.org/html/rfc3079">RFC 3079, Deriving Keys for use with Microsoft
 *     Point-to-Point Encryption (MPPE)</a>
 */
public class EapMsChapV2MethodStateMachine extends EapMethodStateMachine {
    private final EapMsChapV2Config mEapMsChapV2Config;
    private final SecureRandom mSecureRandom;

    public EapMsChapV2MethodStateMachine(
            EapMsChapV2Config eapMsChapV2Config, SecureRandom secureRandom) {
        this.mEapMsChapV2Config = eapMsChapV2Config;
        this.mSecureRandom = secureRandom;

        transitionTo(new CreatedState());
    }

    @Override
    @EapMethod
    int getEapMethod() {
        return EAP_TYPE_MSCHAP_V2;
    }

    @Override
    EapResult handleEapNotification(String tag, EapMessage message) {
        return EapStateMachine.handleNotification(tag, message);
    }

    protected class CreatedState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/140571186): implement CreatedState
            return null;
        }
    }

    protected class ChallengeState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/140320101): implement ChallengeState
            return null;
        }
    }

    protected class PostChallengeState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/140322003): implement PostChallengeState
            return null;
        }
    }
}
