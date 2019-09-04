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
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapTestMessageDefinitions.COMPUTED_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_CLIENT_ERROR_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_IDENTITY;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SIM_RESPONSE_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.KC_1;
import static com.android.ike.eap.message.EapTestMessageDefinitions.KC_2;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_AUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_AUT_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_ENCR;
import static com.android.ike.eap.message.EapTestMessageDefinitions.K_ENCR_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MAC_INPUT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK_STRING;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ORIGINAL_MAC;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SRES_1;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SRES_BYTES;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_CHALLENGE;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_CLIENT_ERROR;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_START;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AT_IDENTITY;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.IDENTITY;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.NONCE_MT;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.NONCE_MT_STRING;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_1_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_2_BYTES;
import static com.android.ike.eap.statemachine.EapSimAkaMethodStateMachine.KEY_LEN;
import static com.android.ike.eap.statemachine.EapSimAkaMethodStateMachine.MAC_ALGORITHM_STRING;
import static com.android.ike.eap.statemachine.EapSimAkaMethodStateMachine.MASTER_KEY_GENERATION_ALG;
import static com.android.ike.eap.statemachine.EapSimAkaMethodStateMachine.SESSION_KEY_LENGTH;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.telephony.TelephonyManager;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapSessionConfig.EapSimConfig;
import com.android.ike.eap.crypto.Fips186_2Prf;
import com.android.ike.eap.exceptions.simaka.EapSimAkaAuthenticationFailureException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtIdentity;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtMac;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtRandSim;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtSelectedVersion;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData;
import com.android.ike.eap.message.simaka.EapSimTypeData;

import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class EapSimAkaMethodStateMachineTest {
    private static final String TAG = EapSimAkaMethodStateMachineTest.class.getSimpleName();
    private static final int SUB_ID = 1;
    private static final int AT_RAND_LEN = 36;
    private static final String VERSIONS_STRING = "0001";
    private static final String SELECTED_VERSION = "0001";
    private static final byte[] SHA_1_INPUT = hexStringToByteArray("0123456789ABCDEF");
    private static final byte[] FORMATTED_UICC_CHALLENGE =
            hexStringToByteArray("1000112233445566778899AABBCCDDEEFF");
    private static final String BASE_64_CHALLENGE = "EAARIjNEVWZ3iJmqu8zd7v8=";
    private static final String BASE_64_RESPONSE = "BBEiM0QIAQIDBAUGBwg=";
    private static final byte[] UICC_RESPONSE =
            hexStringToByteArray("04" + SRES_1 + "08" + KC_1);

    // K_encr + K_aut + MSK + EMSK
    private static final int PRF_OUTPUT_BYTES = (2 * KEY_LEN) + (2 * SESSION_KEY_LENGTH);

    private TelephonyManager mMockTelephonyManager;
    private EapSimConfig mEapSimConfig;
    private EapSimAkaMethodStateMachine mStateMachine;

    @Before
    public void setUp() {
        mMockTelephonyManager = mock(TelephonyManager.class);
        mEapSimConfig = new EapSimConfig(SUB_ID, TelephonyManager.APPTYPE_USIM);

        mStateMachine =
                new EapSimAkaMethodStateMachine(mMockTelephonyManager, mEapSimConfig) {
                    @Override
                    EapSimAkaTypeData getEapSimAkaTypeData(AtClientErrorCode clientErrorCode) {
                        return new EapSimTypeData(
                                EAP_SIM_CLIENT_ERROR, Arrays.asList(clientErrorCode));
                    }

                    @Override
                    EapSimAkaTypeData getEapSimAkaTypeData(
                            int eapSubtype, List<EapSimAkaAttribute> attributes) {
                        return new EapSimTypeData(eapSubtype, attributes);
                    }

                    @Override
                    int getEapMethod() {
                        return EAP_TYPE_SIM;
                    }
                };
        mStateMachine = spy(mStateMachine);
    }

    @Test
    public void testBuildClientErrorResponse() {
        AtClientErrorCode errorCode = AtClientErrorCode.UNSUPPORTED_VERSION;

        EapResult result =
                mStateMachine.buildClientErrorResponse(ID_INT, EAP_TYPE_SIM, errorCode);
        assertTrue(result instanceof EapResult.EapResponse);
        EapResult.EapResponse eapResponse = (EapResult.EapResponse) result;
        assertArrayEquals(EAP_SIM_CLIENT_ERROR_RESPONSE, eapResponse.packet);
    }

    @Test
    public void testBuildResponseMessage() throws Exception {
        List<EapSimAkaAttribute> attributes = new ArrayList<>();
        attributes.add(new AtSelectedVersion(1));
        attributes.add(new AtIdentity(AT_IDENTITY.length, IDENTITY));
        int identifier = ID_INT;

        EapResult result =
                mStateMachine.buildResponseMessage(
                        EAP_TYPE_SIM,
                        EAP_SIM_START,
                        identifier,
                        attributes);
        assertTrue(result instanceof EapResult);
        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_RESPONSE_PACKET, eapResponse.packet);
    }

    @Test
    public void testGenerateAndPersistKeys() {
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

        mStateMachine.generateAndPersistKeys(TAG, mockSha1, mockFips186_2Prf, mkInput);
        assertArrayEquals(K_ENCR, mStateMachine.mKEncr);
        assertArrayEquals(K_AUT, mStateMachine.mKAut);
        assertArrayEquals(MSK, mStateMachine.mMsk);
        assertArrayEquals(EMSK, mStateMachine.mEmsk);

        verify(mockSha1).digest(eq(mkInput));
        verify(mockFips186_2Prf).getRandom(eq(MK), eq(PRF_OUTPUT_BYTES));
        verifyNoMoreInteractions(mockSha1, mockFips186_2Prf);
    }

    /**
     * Test that we can actually instantiate and use the SHA-1algorithm.
     */
    @Test
    public void testCreateSha1() throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance(MASTER_KEY_GENERATION_ALG);
        byte[] sha1Result = sha1.digest(SHA_1_INPUT);
        assertFalse(Arrays.equals(SHA_1_INPUT, sha1Result));
    }

    /**
     * Test that we can actually instantiate and use the HMAC-SHA-1 algorithm.
     */
    @Test
    public void testCreateHmacSha1() throws Exception {
        Mac macAlgorithm = Mac.getInstance(MAC_ALGORITHM_STRING);
        macAlgorithm.init(new SecretKeySpec(K_AUT, MAC_ALGORITHM_STRING));
        byte[] mac = macAlgorithm.doFinal(MAC_INPUT);
        assertFalse(Arrays.equals(MAC_INPUT, mac));
    }

    @Test
    public void testProcessUiccAuthentication() throws Exception {
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE)).thenReturn(BASE_64_RESPONSE);

        byte[] result =
                mStateMachine.processUiccAuthentication(
                        TAG,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        FORMATTED_UICC_CHALLENGE);

        assertArrayEquals(UICC_RESPONSE, result);
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE);
        verifyNoMoreInteractions(mMockTelephonyManager);
    }

    @Test
    public void testProcessUiccAuthenticationNullResponse() throws Exception {
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE)).thenReturn(null);

        try {
            mStateMachine.processUiccAuthentication(
                    TAG,
                    TelephonyManager.AUTHTYPE_EAP_AKA,
                    FORMATTED_UICC_CHALLENGE);
            fail("EapSimAkaAuthenticationFailureException expected for null TelMan response");
        } catch (EapSimAkaAuthenticationFailureException expected) {
        }

        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE_64_CHALLENGE);
        verifyNoMoreInteractions(mMockTelephonyManager);
    }

    @Test
    public void testGetMac() throws Exception {
        AtMac atMac = new AtMac(ORIGINAL_MAC);
        AtRandSim atRandSim = new AtRandSim(AT_RAND_LEN, RAND_1_BYTES, RAND_2_BYTES);
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(EAP_SIM_CHALLENGE, Arrays.asList(atRandSim, atMac));

        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(MAC_INPUT))).thenReturn(COMPUTED_MAC);
        mStateMachine.mMacAlgorithm = mockMac;

        byte[] mac = mStateMachine.getMac(EAP_CODE_REQUEST, ID_INT, eapSimTypeData, NONCE_MT);
        assertArrayEquals(COMPUTED_MAC, mac);
        AtMac postCalculationAtMac = (AtMac) eapSimTypeData.attributeMap.get(EAP_AT_MAC);
        assertArrayEquals(ORIGINAL_MAC, postCalculationAtMac.mac);

        verify(mockMac).doFinal(eq(MAC_INPUT));
        verifyNoMoreInteractions(mockMac);
    }

    @Test
    public void testGetMacNoMacAlgorithm() throws Exception {
        try {
            mStateMachine.getMac(EAP_CODE_REQUEST, ID_INT, null, null);
            fail("Expected IllegalStateException if Mac not set");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testReceivedValidMac() throws Exception {
        AtMac atMac = new AtMac(ORIGINAL_MAC);
        AtRandSim atRandSim = new AtRandSim(AT_RAND_LEN, RAND_1_BYTES, RAND_2_BYTES);
        EapSimTypeData eapSimTypeData =
                new EapSimTypeData(EAP_SIM_CHALLENGE, Arrays.asList(atRandSim, atMac));
        EapData eapData = new EapData(EAP_TYPE_SIM, new byte[0]);
        EapMessage message = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        doReturn(ORIGINAL_MAC)
                .when(mStateMachine)
                .getMac(eq(EAP_CODE_REQUEST), eq(ID_INT), eq(eapSimTypeData), eq(NONCE_MT));

        assertTrue(mStateMachine.isValidMac(TAG, message, eapSimTypeData, NONCE_MT));

        doReturn(new byte[0])
                .when(mStateMachine)
                .getMac(eq(EAP_CODE_REQUEST), eq(ID_INT), eq(eapSimTypeData), eq(NONCE_MT));

        assertFalse(mStateMachine.isValidMac(TAG, message, eapSimTypeData, NONCE_MT));

        verify(mStateMachine, times(2))
                .getMac(eq(EAP_CODE_REQUEST), eq(ID_INT), eq(eapSimTypeData), eq(NONCE_MT));
    }

    @Test
    public void testBuildResponseMessageWithMac() {
        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal(eq(EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT))).thenReturn(COMPUTED_MAC);
        mStateMachine.mMacAlgorithm = mockMac;

        EapResult result =
                mStateMachine.buildResponseMessageWithMac(ID_INT, EAP_SIM_CHALLENGE, SRES_BYTES);

        EapResponse eapResponse = (EapResponse) result;
        assertArrayEquals(EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC, eapResponse.packet);
        verify(mockMac).doFinal(eq(EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT));
        verifyNoMoreInteractions(mockMac);
    }
}
