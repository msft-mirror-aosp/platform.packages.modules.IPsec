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

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.EapData.EAP_IDENTITY;
import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.CK_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_CHALLENGE_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_SYNCHRONIZATION_FAILURE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_UICC_RESP_INVALID_TAG;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_UICC_RESP_SUCCESS_BASE_64;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_UICC_RESP_SYNCHRONIZE_BASE_64;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.IK_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AUTN_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AUTS_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.IDENTITY;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_1_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RES_BYTES;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.telephony.TelephonyManager;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaAuthenticationFailureException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaInvalidLengthException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapAkaTypeData;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtAutn;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtMac;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtRandAka;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData.DecodeResult;
import com.android.ike.eap.statemachine.EapAkaMethodStateMachine.ChallengeState;
import com.android.ike.eap.statemachine.EapAkaMethodStateMachine.ChallengeState.RandChallengeResult;
import com.android.ike.eap.statemachine.EapMethodStateMachine.FinalState;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

public class EapAkaChallengeStateTest extends EapAkaStateTest {
    private ChallengeState mChallengeState;

    // '10' + RAND_1_BYTES + '10' + AUTN_BYTES
    private static final String BASE_64_CHALLENGE =
            "EAARIjNEVWZ3iJmqu8zd7v8QASNFZ4mrze/+3LqYdlQyEA==";

    /**
     * Process to generate MAC:
     *
     * message =    01100044 | EAP-Request, ID, length in bytes
     *              17010000 | EAP-AKA, AKA-Challenge, padding
     *              0105000000112233445566778899AABBCCDDEEFF | AT_RAND
     *              020500000123456789ABCDEFFEDCBA9876543210 | AT_AUTN
     *              0B05000000000000000000000000000000000000 | AT_MAC (zeroed out)
     *
     * MK = SHA-1(message)
     * K_encr, K_aut, MSK, EMSK = PRF(MK)
     * MAC = HMAC-SHA-1(K_aut, message)
     */
    private static final byte[] REQUEST_MAC_BYTES =
            hexStringToByteArray("3EB97A1D0E62894FD0DA384D24D8983C");

    @Before
    public void setUp() {
        super.setUp();

        mChallengeState = mEapAkaMethodStateMachine.new ChallengeState(IDENTITY);
        mEapAkaMethodStateMachine.transitionTo(mChallengeState);
    }

    @Test
    public void testProcessIncorrectEapMethodType() throws Exception {
        EapData eapData = new EapData(EAP_IDENTITY, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        EapResult result = mChallengeState.process(eapMessage);
        EapError eapError = (EapError) result;
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
    }

    @Test
    public void testProcessSuccess() throws Exception {
        System.arraycopy(MSK, 0, mEapAkaMethodStateMachine.mMsk, 0, MSK.length);
        System.arraycopy(EMSK, 0, mEapAkaMethodStateMachine.mEmsk, 0, EMSK.length);

        mChallengeState.mHadSuccessfulChallenge = true;
        EapMessage input = new EapMessage(EAP_CODE_SUCCESS, ID_INT, null);

        EapSuccess eapSuccess = (EapSuccess) mEapAkaMethodStateMachine.process(input);
        assertArrayEquals(MSK, eapSuccess.msk);
        assertArrayEquals(EMSK, eapSuccess.emsk);
        assertTrue(mEapAkaMethodStateMachine.getState() instanceof FinalState);
    }

    @Test
    public void testProcessInvalidSuccess() throws Exception {
        EapMessage input = new EapMessage(EAP_CODE_SUCCESS, ID_INT, null);

        EapError eapError = (EapError) mEapAkaMethodStateMachine.process(input);
        assertTrue(eapError.cause instanceof EapInvalidRequestException);
    }

    @Test
    public void testProcessFailure() throws Exception {
        EapMessage input = new EapMessage(EAP_CODE_FAILURE, ID_INT, null);
        EapResult result = mEapAkaMethodStateMachine.process(input);
        assertTrue(mEapAkaMethodStateMachine.getState() instanceof FinalState);

        assertTrue(result instanceof EapFailure);
    }

    @Test
    public void testProcessMissingAtRand() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(REQUEST_MAC_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(EAP_AKA_CHALLENGE, Arrays.asList(atAutn, atMac)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

        EapResponse eapResponse = (EapResponse) mEapAkaMethodStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }

    @Test
    public void testProcessMissingAtAutn() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtMac atMac = new AtMac(REQUEST_MAC_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(EAP_AKA_CHALLENGE, Arrays.asList(atRandAka, atMac)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

        EapResponse eapResponse = (EapResponse) mEapAkaMethodStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }

    @Test
    public void testProcessMissingAtMac() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(EAP_AKA_CHALLENGE, Arrays.asList(atRandAka, atAutn)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

        EapResponse eapResponse = (EapResponse) mEapAkaMethodStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS, eapResponse.packet);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }

    @Test
    public void testRandChallengeResultConstructor() throws Exception {
        RandChallengeResult result =
                mChallengeState.new RandChallengeResult(RES_BYTES, IK_BYTES, CK_BYTES);
        assertArrayEquals(RES_BYTES, result.res);
        assertArrayEquals(IK_BYTES, result.ik);
        assertArrayEquals(CK_BYTES, result.ck);
        assertNull(result.auts);

        result = mChallengeState.new RandChallengeResult(AUTS_BYTES);
        assertArrayEquals(AUTS_BYTES, result.auts);
        assertNull(result.res);
        assertNull(result.ik);
        assertNull(result.ck);

        try {
            mChallengeState.new RandChallengeResult(new byte[0], IK_BYTES, CK_BYTES);
            fail("Expected EapSimAkaInvalidLengthException for invalid RES length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }

        try {
            mChallengeState.new RandChallengeResult(RES_BYTES, new byte[0], CK_BYTES);
            fail("Expected EapSimAkaInvalidLengthException for invalid IK length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }

        try {
            mChallengeState.new RandChallengeResult(RES_BYTES, IK_BYTES, new byte[0]);
            fail("Expected EapSimAkaInvalidLengthException for invalid CK length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }

        try {
            mChallengeState.new RandChallengeResult(new byte[0]);
            fail("Expected EapSimAkaInvalidLengthException for invalid AUTS length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }
    }

    @Test
    public void testProcessIccAuthenticationNullResponse() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(REQUEST_MAC_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(
                                EAP_AKA_CHALLENGE,
                                Arrays.asList(atRandAka, atAutn, atMac)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE))
                .thenReturn(null);

        EapError eapError = (EapError) mEapAkaMethodStateMachine.process(eapMessage);
        assertTrue(eapError.cause instanceof EapSimAkaAuthenticationFailureException);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE);
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }

    @Test
    public void testProcessIccAuthenticationInvalidTag() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(REQUEST_MAC_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(
                                EAP_AKA_CHALLENGE,
                                Arrays.asList(atRandAka, atAutn, atMac)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE))
                .thenReturn(EAP_AKA_UICC_RESP_INVALID_TAG);

        EapError eapError = (EapError) mEapAkaMethodStateMachine.process(eapMessage);
        assertTrue(eapError.cause instanceof EapSimAkaAuthenticationFailureException);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE);
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }

    @Test
    public void testProcessIccAuthenticationSynchronizeTag() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(REQUEST_MAC_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(
                                EAP_AKA_CHALLENGE,
                                Arrays.asList(atRandAka, atAutn, atMac)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE))
                .thenReturn(EAP_AKA_UICC_RESP_SYNCHRONIZE_BASE_64);

        EapResponse eapResponse = (EapResponse) mEapAkaMethodStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_SYNCHRONIZATION_FAILURE, eapResponse.packet);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE);
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }

    @Test
    public void testProcessValidChallenge() throws Exception {
        // TODO(b/140258387): update test vectors with externally generated values

        EapData eapData = new EapData(EAP_TYPE_AKA, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(REQUEST_MAC_BYTES);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaTypeData(
                                EAP_AKA_CHALLENGE, Arrays.asList(atRandAka, atAutn, atMac)));
        when(mMockEapAkaTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);
        when(mMockTelephonyManager.getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE))
                .thenReturn(EAP_AKA_UICC_RESP_SUCCESS_BASE_64);

        EapResponse eapResponse = (EapResponse) mEapAkaMethodStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_CHALLENGE_RESPONSE, eapResponse.packet);

        verify(mMockEapAkaTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE);
        verifyNoMoreInteractions(mMockEapAkaTypeDataDecoder, mMockTelephonyManager);
    }
}
