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

import static com.android.ike.eap.message.EapData.EAP_IDENTITY;
import static com.android.ike.eap.message.EapData.EAP_NAK;
import static com.android.ike.eap.message.EapData.EAP_NOTIFICATION;
import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA_PRIME;
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;

import android.annotation.NonNull;
import android.content.Context;
import android.util.Log;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.UnsupportedEapTypeException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.utils.SimpleStateMachine;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.charset.StandardCharsets;

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
    @VisibleForTesting
    protected static final byte[] DEFAULT_IDENTITY = new byte[0];

    private final Context mContext;

    public EapStateMachine(@NonNull Context context) {
        this.mContext = context;
        transitionTo(new CreatedState());
    }

    @VisibleForTesting
    protected SimpleStateMachine.SimpleState getState() {
        return mState;
    }

    @VisibleForTesting
    protected void transitionTo(EapState newState) {
        super.transitionTo(newState);
    }

    @VisibleForTesting
    protected EapResult transitionAndProcess(EapState newState, byte[] packet) {
        return super.transitionAndProcess(newState, packet);
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
                return new DecodeResult(EapMessage.getNakResponse(ex.eapIdentifier));
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
        private final String mTAG = CreatedState.class.getSimpleName();

        public EapResult process(@NonNull byte[] packet) {
            DecodeResult decodeResult = decode(packet);
            if (!decodeResult.isValidEapMessage()) {
                return decodeResult.eapResult;
            }
            EapMessage message = decodeResult.eapMessage;

            if (message.eapCode != EAP_CODE_REQUEST) {
                return new EapError(
                        new EapInvalidRequestException("Received non EAP-Request in CreatedState"));
            }

            // EapMessage#validate verifies that all EapMessage objects representing
            // EAP-Request packets have a Type value
            switch (message.eapData.eapType) {
                case EAP_NOTIFICATION:
                    return handleNotification(mTAG, message);

                case EAP_IDENTITY:
                    return transitionAndProcess(new IdentityState(), packet);

                // all EAP methods should be handled by MethodState
                default:
                    return transitionAndProcess(new MethodState(message.eapData.eapType), packet);
            }
        }
    }

    protected class IdentityState extends EapState {
        private final String mTAG = IdentityState.class.getSimpleName();

        public EapResult process(@NonNull byte[] packet) {
            DecodeResult decodeResult = decode(packet);
            if (!decodeResult.isValidEapMessage()) {
                return decodeResult.eapResult;
            }
            EapMessage message = decodeResult.eapMessage;

            if (message.eapCode != EAP_CODE_REQUEST) {
                return new EapError(new EapInvalidRequestException(
                        "Received non EAP-Request in IdentityState"));
            }

            // EapMessage#validate verifies that all EapMessage objects representing
            // EAP-Request packets have a Type value
            switch (message.eapData.eapType) {
                case EAP_NOTIFICATION:
                    return handleNotification(mTAG, message);

                case EAP_IDENTITY:
                    // TODO(b/133794339): identity placeholder should be replaced with a real value
                    return getIdentityResponse(message.eapIdentifier, DEFAULT_IDENTITY);

                // all EAP methods should be handled by MethodState
                default:
                    return transitionAndProcess(new MethodState(message.eapData.eapType), packet);
            }
        }

        @VisibleForTesting
        EapResult getIdentityResponse(int eapIdentifier, byte[] identity) {
            try {
                EapData identityData = new EapData(EAP_IDENTITY, identity);
                return EapResponse.getEapResponse(
                        new EapMessage(EAP_CODE_RESPONSE, eapIdentifier, identityData));
            } catch (EapSilentException ex) {
                // this should never happen - only identifier and identity bytes are variable
                Log.wtf(mTAG,  "Failed to create Identity response for message with identifier="
                        + eapIdentifier);
                return new EapError(ex);
            }
        }
    }

    protected class MethodState extends EapState {
        private final String mTAG = MethodState.class.getSimpleName();

        private final EapMethodStateMachine mEapMethodStateMachine;

        protected MethodState(int eapType) {
            switch (eapType) {
                case EAP_TYPE_AKA:
                    // TODO(b/133878992): implement and use EapAkaStateMachine
                    mEapMethodStateMachine = new EapMethodStateMachine() {};
                    break;
                case EAP_TYPE_AKA_PRIME:
                    // TODO(b/133878093): implement EapAkaPrimeStateMachine
                    mEapMethodStateMachine = new EapMethodStateMachine() {};
                    break;
                case EAP_TYPE_SIM:
                    // TODO(133879839): implement EapSimStateMachine
                    mEapMethodStateMachine = new EapMethodStateMachine() {};
                    break;

                default:
                    // received unsupported EAP Type. This should never happen.
                    Log.e(mTAG, "Received unsupported EAP Type=" + eapType);
                    throw new IllegalArgumentException(
                            "Received unsupported EAP Type in MethodState constructor");
            }
        }

        public EapResult process(@NonNull byte[] packet) {
            DecodeResult decodeResult = decode(packet);
            if (!decodeResult.isValidEapMessage()) {
                return decodeResult.eapResult;
            }

            return mEapMethodStateMachine.process(decodeResult.eapMessage);
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

    private EapResult handleNotification(String tag, EapMessage message) {
        // Type-Data will be UTF-8 encoded ISO 10646 characters (RFC 3748 Section 5.2)
        String content = new String(message.eapData.eapTypeData, StandardCharsets.UTF_8);
        Log.i(tag, "Received EAP-Request/Notification: [" + content + "]");
        return EapMessage.getNotificationResponse(message.eapIdentifier);
    }
}
