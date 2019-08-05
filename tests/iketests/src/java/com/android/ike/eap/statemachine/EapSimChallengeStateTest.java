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
import static com.android.ike.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.CHALLENGE_RESPONSE_INVALID_KC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.CHALLENGE_RESPONSE_INVALID_SRES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.COMPUTED_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_IDENTITY;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_IDENTITY_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.KC_1;
import static com.android.ike.eap.message.EapTestMessageDefinitions.KC_1_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.KC_2;
import static com.android.ike.eap.message.EapTestMessageDefinitions.KC_2_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_AUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_AUT_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_ENCR;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_ENCR_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MAC_INPUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ORIGINAL_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.RETURNED_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SRES_1_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SRES_2_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.VALID_CHALLENGE_RESPONSE;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.NONCE_MT;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.NONCE_MT_STRING;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_1;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_1_BYTES;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_2;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_2_BYTES;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.crypto.Fips186_2Prf;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.exceptions.EapSimInvalidLengthException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtMac;
import com.android.ike.eap.message.EapSimAttribute.AtNonceMt;
import com.android.ike.eap.message.EapSimAttribute.AtRand;
import com.android.ike.eap.message.EapSimTypeData;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.ChallengeState;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.ChallengeState.RandChallengeResult;
import com.android.ike.eap.statemachine.EapSimMethodStateMachine.FinalState;

import org.junit.Test;

import java.nio.BufferUnderflowException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class EapSimChallengeStateTest extends EapSimStateTest {
    private static final int EAP_REQUEST = 1;
    private static final int EAP_SIM_CHALLENGE = 11;
    private static final int EAP_AT_RAND = 1;
    private static final int EAP_AT_MAC = 11;
    private static final int VALID_SRES_LENGTH = 4;
    private static final int INVALID_SRES_LENGTH = 5;
    private static final int VALID_KC_LENGTH = 8;
    private static final int INVALID_KC_LENGTH = 9;
    private static final int AT_RAND_LENGTH = 36;
    private static final int APPTYPE_SIM = 1;
    private static final int AUTHTYPE_EAP_SIM = 128;
    private static final int AT_RAND_LEN = 36;
    private static final int SUB_ID = 1;
    private static final List<Integer> VERSIONS = Arrays.asList(1);
    private static final String VERSIONS_STRING = "0001";
    private static final String SELECTED_VERSION = "0001";
    private static final int PRF_OUTPUT_BYTES = 16 + 16 + 64 + 64; // K_encr + K_aut + MSK + EMSK

    // Base64 of {@link EapTestAttributeDefinitions#RAND_1}
    private static final String BASE_64_RAND_1 = "ABEiM0RVZneImaq7zN3u/w==";

    // Base64 of {@link EapTestAttributeDefinitions#RAND_2}
    private static final String BASE_64_RAND_2 = "/+7dzLuqmYh3ZlVEMyIRAA==";

    // Base64 of "04" + SRES_1 + "08" + KC_1
    private static final String BASE_64_RESP_1 = "BBEiM0QIAQIDBAUGBwg=";

    // Base64 of "04" + SRES_2 + "08" + KC_2
    private static final String BASE_64_RESP_2 = "BEQzIhEICAcGBQQDAgE=";

    // Base64 of "04" + SRES_1 + '081122"
    private static final String BASE_64_INVALID_RESP = "BBEiM0QIESI=";

    private static final byte[] SHA_1_INPUT = hexStringToByteArray("0123456789ABCDEF");

    private AtNonceMt mAtNonceMt;
    private ChallengeState mChallengeState;

    @Override
    public void setUp() {
        super.setUp();

        try {
            mAtNonceMt = new AtNonceMt(NONCE_MT);
        } catch (EapSimInvalidAttributeException ex) {
            // this will never happen
        }
        mChallengeState = mEapSimMethodStateMachine
                .new ChallengeState(VERSIONS, mAtNonceMt, EAP_SIM_IDENTITY_BYTES);
        mEapSimMethodStateMachine.transitionTo(mChallengeState);
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
        System.arraycopy(MSK, 0, mChallengeState.mMsk, 0, MSK.length);
        System.arraycopy(EMSK, 0, mChallengeState.mEmsk, 0, EMSK.length);

        EapMessage input = new EapMessage(EAP_CODE_SUCCESS, ID_INT, null);
        EapResult result = mEapSimMethodStateMachine.process(input);
        assertTrue(mEapSimMethodStateMachine.getState() instanceof FinalState);

        EapSuccess eapSuccess = (EapSuccess) result;
        assertArrayEquals(MSK, eapSuccess.msk);
        assertArrayEquals(EMSK, eapSuccess.emsk);
    }

    @Test
    public void testProcessFailure() throws Exception {
        EapMessage input = new EapMessage(EAP_CODE_FAILURE, ID_INT, null);
        EapResult result = mEapSimMethodStateMachine.process(input);
        assertTrue(mEapSimMethodStateMachine.getState() instanceof FinalState);

        assertTrue(result instanceof EapFailure);
    }

    @Test
    public void testIsValidChallengeAttributes() {
        LinkedHashMap<Integer, EapSimAttribute> attributeMap = new LinkedHashMap<>();
        EapSimTypeData eapSimTypeData = new EapSimTypeData(EAP_SIM_CHALLENGE, attributeMap);
        assertFalse(mChallengeState.isValidChallengeAttributes(eapSimTypeData));

        attributeMap.put(EAP_AT_RAND, null); // value doesn't matter, just need key
        eapSimTypeData = new EapSimTypeData(EAP_SIM_CHALLENGE, attributeMap);
        assertFalse(mChallengeState.isValidChallengeAttributes(eapSimTypeData));

        attributeMap.put(EAP_AT_MAC, null); // value doesn't matter, just need key
        eapSimTypeData = new EapSimTypeData(EAP_SIM_CHALLENGE, attributeMap);
        assertTrue(mChallengeState.isValidChallengeAttributes(eapSimTypeData));
    }

    @Test
    public void testRandChallengeResultConstructor() {
        try {
            mChallengeState.new RandChallengeResult(
                    new byte[VALID_SRES_LENGTH], new byte[INVALID_KC_LENGTH]);
            fail("EapSimInvalidLengthException expected for invalid SRES lengths");
        } catch (EapSimInvalidLengthException expected) {
        }

        try {
            mChallengeState.new RandChallengeResult(
                    new byte[INVALID_SRES_LENGTH], new byte[VALID_KC_LENGTH]);
            fail("EapSimInvalidLengthException expected for invalid Kc lengths");
        } catch (EapSimInvalidLengthException expected) {
        }
    }

    @Test
    public void testRandChallengeResultEquals() throws Exception {
        RandChallengeResult resultA =
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES);
        RandChallengeResult resultB =
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES);
        RandChallengeResult resultC =
                mChallengeState.new RandChallengeResult(SRES_2_BYTES, KC_2_BYTES);

        assertEquals(resultA, resultB);
        assertNotEquals(resultA, resultC);
    }

    @Test
    public void testRandChallengeResultHashCode() throws Exception {
        RandChallengeResult resultA =
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES);
        RandChallengeResult resultB =
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES);
        RandChallengeResult resultC =
                mChallengeState.new RandChallengeResult(SRES_2_BYTES, KC_2_BYTES);

        assertEquals(resultA.hashCode(), resultB.hashCode());
        assertNotEquals(resultA.hashCode(), resultC.hashCode());
    }

    @Test
    public void testGetRandChallengeResultFromResponse() throws Exception {
        RandChallengeResult result =
                mChallengeState.getRandChallengeResultFromResponse(VALID_CHALLENGE_RESPONSE);

        assertArrayEquals(SRES_1_BYTES, result.sres);
        assertArrayEquals(KC_1_BYTES, result.kc);
    }

    @Test
    public void testGetRandChallengeResultFromResponseInvalidSres() {
        try {
            mChallengeState.getRandChallengeResultFromResponse(CHALLENGE_RESPONSE_INVALID_SRES);
            fail("EapSimInvalidLengthException expected for invalid SRES_1 length");
        } catch (EapSimInvalidLengthException expected) {
        }
    }

    @Test
    public void testGetRandChallengeResultFromResponseInvalidKc() {
        try {
            mChallengeState.getRandChallengeResultFromResponse(CHALLENGE_RESPONSE_INVALID_KC);
            fail("EapSimInvalidLengthException expected for invalid KC length");
        } catch (EapSimInvalidLengthException expected) {
        }
    }

    @Test
    public void testGetRandChallengeResults() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(EAP_SIM_CHALLENGE, Arrays.asList(
                        new AtRand(AT_RAND_LENGTH,
                                hexStringToByteArray(RAND_1),
                                hexStringToByteArray(RAND_2))));

        when(mMockTelephonyManager
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_1))
                .thenReturn(BASE_64_RESP_1);
        when(mMockTelephonyManager
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_2))
                .thenReturn(BASE_64_RESP_2);

        List<RandChallengeResult> actualResult =
                mChallengeState.getRandChallengeResults(eapSimTypeData);

        List<RandChallengeResult> expectedResult = Arrays.asList(
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES),
                mChallengeState.new RandChallengeResult(SRES_2_BYTES, KC_2_BYTES));
        assertEquals(expectedResult, actualResult);

        verify(mMockTelephonyManager)
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_1);
        verify(mMockTelephonyManager)
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_2);
        verifyNoMoreInteractions(mMockTelephonyManager);
    }

    @Test
    public void testGetRandChallengeResultsBufferUnderflow() throws Exception {
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(EAP_SIM_CHALLENGE, Arrays.asList(
                        new AtRand(AT_RAND_LENGTH,
                                hexStringToByteArray(RAND_1),
                                hexStringToByteArray(RAND_2))));

        when(mMockTelephonyManager
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_1))
                .thenReturn(BASE_64_RESP_1);
        when(mMockTelephonyManager
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_2))
                .thenReturn(BASE_64_INVALID_RESP);

        try {
            mChallengeState.getRandChallengeResults(eapSimTypeData);
            fail("BufferUnderflowException expected for short Kc value");
        } catch (BufferUnderflowException ex) {
        }

        verify(mMockTelephonyManager)
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_1);
        verify(mMockTelephonyManager)
                .getIccAuthentication(APPTYPE_SIM, AUTHTYPE_EAP_SIM, BASE_64_RAND_2);
        verifyNoMoreInteractions(mMockTelephonyManager);
    }

    @Test
    public void testGenerateAndPersistKeys() throws Exception {
        byte[] mkInput = hexStringToByteArray(
                EAP_SIM_IDENTITY
                + KC_1
                + KC_2
                + NONCE_MT_STRING
                + VERSIONS_STRING
                + SELECTED_VERSION);
        MessageDigest mockSha1 = mock(MessageDigest.class);
        when(mockSha1.digest(eq(mkInput))).thenReturn(MK);

        byte[] keys = hexStringToByteArray(K_ENCR_STRING + K_AUT_STRING + MSK_STRING + EMSK_STRING);
        Fips186_2Prf mockFips186_2Prf = mock(Fips186_2Prf.class);
        when(mockFips186_2Prf.getRandom(eq(MK), eq(PRF_OUTPUT_BYTES))).thenReturn(keys);

        List<RandChallengeResult> randChallengeResults = Arrays.asList(
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES),
                mChallengeState.new RandChallengeResult(SRES_2_BYTES, KC_2_BYTES));

        mChallengeState.generateAndPersistKeys(mockSha1, mockFips186_2Prf, randChallengeResults);
        assertArrayEquals(K_ENCR, mChallengeState.mKEncr);
        assertArrayEquals(K_AUT, mChallengeState.mKAut);
        assertArrayEquals(MSK, mChallengeState.mMsk);
        assertArrayEquals(EMSK, mChallengeState.mEmsk);

        verify(mockSha1).digest(eq(mkInput));
        verify(mockFips186_2Prf).getRandom(eq(MK), eq(PRF_OUTPUT_BYTES));
        verifyNoMoreInteractions(mockSha1, mockFips186_2Prf);
    }

    @Test
    public void testGetMac() throws Exception {
        // test for EAP-Request/SIM/Challenge. MAC is calculated over the EapMessage and Nonce
        // (RFC 4186 Section 9.3)
        AtMac atMac = new AtMac(ORIGINAL_MAC);
        AtRand atRand = new AtRand(AT_RAND_LEN, RAND_1_BYTES, RAND_2_BYTES);
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(EAP_SIM_CHALLENGE, Arrays.asList(atRand, atMac));

        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(MAC_INPUT))).thenReturn(COMPUTED_MAC);

        byte[] mac = mChallengeState.getMac(mockMac, EAP_REQUEST, ID_INT, eapSimTypeData, NONCE_MT);
        assertArrayEquals(RETURNED_MAC, mac);
        AtMac postCalculationAtMac = (AtMac) eapSimTypeData.attributeMap.get(EAP_AT_MAC);
        assertArrayEquals(ORIGINAL_MAC, postCalculationAtMac.mac);

        verify(mockMac).doFinal(eq(MAC_INPUT));
        verifyNoMoreInteractions(mockMac);
    }

    /**
     * Test that we can actually instantiate and use the SHA-1 and HMAC-SHA-1 algorithms.
     */
    @Test
    public void testCreateAlgorithms() throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance(mChallengeState.mMasterKeyGenerationAlg);
        byte[] sha1Result = sha1.digest(SHA_1_INPUT);
        assertFalse(Arrays.equals(SHA_1_INPUT, sha1Result));

        Mac macAlgorithm = Mac.getInstance(mChallengeState.mMacAlgorithm);
        macAlgorithm.init(new SecretKeySpec(K_AUT, mChallengeState.mMacAlgorithm));
        byte[] mac = macAlgorithm.doFinal(MAC_INPUT);
        assertFalse(Arrays.equals(MAC_INPUT, mac));
    }

    @Test
    public void testBuildResponseMessageWithMac() throws Exception {
        List<RandChallengeResult> randChallengeResults = Arrays.asList(
                mChallengeState.new RandChallengeResult(SRES_1_BYTES, KC_1_BYTES),
                mChallengeState.new RandChallengeResult(SRES_2_BYTES, KC_2_BYTES));

        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT))).thenReturn(COMPUTED_MAC);

        EapResult result =
                mChallengeState.buildResponseMessageWithMac(mockMac, ID_INT, randChallengeResults);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC, eapResponse.packet);
        verify(mockMac).doFinal(eq(EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT));
        verifyNoMoreInteractions(mockMac);
    }
}
