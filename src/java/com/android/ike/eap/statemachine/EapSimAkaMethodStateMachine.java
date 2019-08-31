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
import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;

import android.telephony.TelephonyManager;
import android.util.Base64;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapSessionConfig.EapUiccConfig;
import com.android.ike.eap.crypto.Fips186_2Prf;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaAuthenticationFailureException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData;
import com.android.ike.utils.Log;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.List;

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
    public static final String MASTER_KEY_GENERATION_ALG = "SHA-1";

    // K_encr and K_aut lengths are 16 bytes (RFC 4186#7, RFC 4187#7)
    public static final int KEY_LEN = 16;

    // Session Key lengths are 64 bytes (RFC 4186#7, RFC 4187#7)
    public static final int SESSION_KEY_LENGTH = 64;

    public final byte[] mKEncr = new byte[KEY_LEN];
    public final byte[] mKAut = new byte[KEY_LEN];
    public final byte[] mMsk = new byte[SESSION_KEY_LENGTH];
    public final byte[] mEmsk = new byte[SESSION_KEY_LENGTH];

    final TelephonyManager mTelephonyManager;
    final EapUiccConfig mEapUiccConfig;

    EapSimAkaMethodStateMachine(TelephonyManager telephonyManager, EapUiccConfig eapUiccConfig) {
        if (telephonyManager == null) {
            throw new IllegalArgumentException("TelephonyManager must be non-null");
        } else if (eapUiccConfig == null) {
            throw new IllegalArgumentException("EapUiccConfig must be non-null");
        }
        this.mTelephonyManager = telephonyManager;
        this.mEapUiccConfig = eapUiccConfig;
    }

    @Override
    EapResult handleEapNotification(String tag, EapMessage message) {
        return EapStateMachine.handleNotification(tag, message);
    }

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

    @VisibleForTesting
    EapResult buildResponseMessage(
            int eapType,
            int eapSubtype,
            int identifier,
            List<EapSimAkaAttribute> attributes) {
        EapSimAkaTypeData eapSimTypeData = getEapSimAkaTypeData(eapSubtype, attributes);
        EapData eapData = new EapData(eapType, eapSimTypeData.encode());

        try {
            EapMessage eapMessage = new EapMessage(EAP_CODE_RESPONSE, identifier, eapData);
            return EapResult.EapResponse.getEapResponse(eapMessage);
        } catch (EapSilentException ex) {
            return new EapResult.EapError(ex);
        }
    }

    @VisibleForTesting
    void generateAndPersistKeys(
            String tag,
            MessageDigest sha1,
            Fips186_2Prf prf,
            byte[] mkInput) {
        byte[] mk = sha1.digest(mkInput);

        // run mk through FIPS 186-2
        int outputBytes = mKEncr.length + mKAut.length + mMsk.length + mEmsk.length;
        byte[] prfResult = prf.getRandom(mk, outputBytes);

        ByteBuffer prfResultBuffer = ByteBuffer.wrap(prfResult);
        prfResultBuffer.get(mKEncr);
        prfResultBuffer.get(mKAut);
        prfResultBuffer.get(mMsk);
        prfResultBuffer.get(mEmsk);

        // Log as hash unless PII debug mode enabled
        LOG.d(tag, "K_encr=" + LOG.pii(mKEncr));
        LOG.d(tag, "K_aut=" + LOG.pii(mKAut));
        LOG.d(tag, "MSK=" + LOG.pii(mMsk));
        LOG.d(tag, "EMSK=" + LOG.pii(mEmsk));
    }

    @VisibleForTesting
    byte[] processUiccAuthentication(String tag, int authType, byte[] formattedChallenge) throws
            EapSimAkaAuthenticationFailureException {
        String base64Challenge = Base64.encodeToString(formattedChallenge, Base64.NO_WRAP);
        String base64Response =
                mTelephonyManager.getIccAuthentication(
                        mEapUiccConfig.apptype,
                        authType,
                        base64Challenge);

        if (base64Response == null) {
            String msg = "UICC authentication failed. Input: "
                    + Log.byteArrayToHexString(formattedChallenge);
            LOG.e(tag, msg);
            throw new EapSimAkaAuthenticationFailureException(msg);
        }

        return Base64.decode(base64Response, Base64.DEFAULT);
    }

    abstract EapSimAkaTypeData getEapSimAkaTypeData(AtClientErrorCode clientErrorCode);
    abstract EapSimAkaTypeData getEapSimAkaTypeData(
            int eapSubtype, List<EapSimAkaAttribute> attributes);
}
