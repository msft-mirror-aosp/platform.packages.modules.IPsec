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

import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData;
import com.android.internal.annotations.VisibleForTesting;

/**
 * EapSimAkaMethodStateMachine represents an abstract state machine for managing EAP-SIM and EAP-AKA
 * sessions.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186">RFC 4186, Extensible Authentication
 * Protocol for Subscriber Identity Modules (EAP-SIM)</a>
 * @see <a href="https://tools.ietf.org/html/rfc4187">RFC 4187, Extensible Authentication
 * Protocol for Authentication and Key Agreement (EAP-AKA)</a>
 */
public abstract class EapSimAkaMethodStateMachine extends EapMethodStateMachine {
    @VisibleForTesting
    EapResult buildClientErrorResponse(
            int eapIdentifier,
            int eapMethodType,
            AtClientErrorCode clientErrorCode) {
        EapSimAkaTypeData eapSimAkaTypeData = getEapSimAkaTypeData(clientErrorCode);
        byte[] encodedTypeData = eapSimAkaTypeData.encode();

        EapData eapData = new EapData(eapMethodType, encodedTypeData);
        try {
            EapMessage response = new EapMessage(EAP_CODE_RESPONSE, eapIdentifier, eapData);
            return EapResult.EapResponse.getEapResponse(response);
        } catch (EapSilentException ex) {
            return new EapResult.EapError(ex);
        }
    }

    abstract EapSimAkaTypeData getEapSimAkaTypeData(AtClientErrorCode clientErrorCode);
}
