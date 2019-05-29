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

import static com.android.ike.eap.message.EapData.EAP_NAK;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;

import android.annotation.NonNull;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.UnsupportedEapTypeException;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.utils.SimpleStateMachine;
import com.android.internal.annotations.VisibleForTesting;

/**
 * EapStateMachine represents the valid paths for a single EAP Authentication procedure.
 *
 * <p>EAP Authentication procedures will always follow the path:
 *
 * CreatedState --> IdentityState --> Method State --+--> SuccessState
 *      |                                 ^          |
 *      +---------------------------------+          +--> FailureState
 *
 */
public class EapStateMachine extends SimpleStateMachine<byte[], EapResult> {
    public EapStateMachine() {
        transitionTo(new CreatedState());
    }

    @VisibleForTesting
    protected SimpleStateMachine.SimpleState getState() {
        return mState;
    }

    protected abstract class EapState extends SimpleState {
        protected DecodeResult decode(@NonNull byte[] packet) {
            if (packet == null) {
                return new DecodeResult(new EapError(
                        new IllegalArgumentException("Attempting to decode null packet")));
            }

            try {
                EapMessage eapMessage = EapMessage.decode(packet);
                if (eapMessage.eapCode == EAP_CODE_RESPONSE) {
                    EapInvalidRequestException cause =
                            new EapInvalidRequestException("Received an EAP-Response message");
                    return new DecodeResult(new EapError(cause));
                } else if (eapMessage.eapCode == EAP_CODE_REQUEST
                        && eapMessage.eapData.eapType == EAP_NAK) {
                    // RFC 3748 Section 5.3.1 states that Nak type is only valid in responses
                    EapInvalidRequestException cause =
                            new EapInvalidRequestException("Received an EAP-Request of type Nak");
                    return new DecodeResult(new EapError(cause));
                }

                return new DecodeResult(eapMessage);
            } catch (UnsupportedEapTypeException ex) {
                EapMessage nak = EapMessage.getNak(ex.eapIdentifier);
                return new DecodeResult(EapResponse.getEapResponse(nak));
            } catch (EapSilentException ex) {
                return new DecodeResult(new EapError(ex));
            }
        }

        protected final class DecodeResult {
            public final EapMessage eapMessage;
            public final EapResult eapResult;

            public DecodeResult(EapMessage eapMessage) {
                this.eapMessage = eapMessage;
                this.eapResult = null;
            }

            public DecodeResult(EapResult eapResult) {
                this.eapMessage = null;
                this.eapResult = eapResult;
            }

            public boolean isValidEapMessage() {
                return eapMessage != null;
            }
        }
    }

    protected class CreatedState extends EapState {
        public EapResult process(@NonNull byte[] packet) {
            DecodeResult decodeResult = decode(packet);
            if (!decodeResult.isValidEapMessage()) {
                return decodeResult.eapResult;
            }
            EapMessage message = decodeResult.eapMessage;
            // TODO(b/133140131): implement logic for state
            return null;
        }
    }

    protected class IdentityState extends EapState {
        public EapResult process(@NonNull byte[] packet) {
            DecodeResult decodeResult = decode(packet);
            if (!decodeResult.isValidEapMessage()) {
                return decodeResult.eapResult;
            }
            EapMessage message = decodeResult.eapMessage;
            // TODO(b/133140131): implement logic for state
            return null;
        }
    }

    protected class MethodState extends EapState {
        public EapResult process(@NonNull byte[] packet) {
            DecodeResult decodeResult = decode(packet);
            if (!decodeResult.isValidEapMessage()) {
                return decodeResult.eapResult;
            }
            EapMessage message = decodeResult.eapMessage;
            // TODO(b/133140131): implement logic for state
            return null;
        }
    }

    protected class SuccessState extends EapState {
        public EapResult process(byte[] packet) {
            return new EapError(new EapInvalidRequestException(
                    "Not possible to process messages in Success State"));
        }
    }

    protected class FailureState extends EapState {
        public EapResult process(byte[] message) {
            return new EapError(new EapInvalidRequestException(
                    "Not possible to process messages in Failure State"));
        }
    }
}
