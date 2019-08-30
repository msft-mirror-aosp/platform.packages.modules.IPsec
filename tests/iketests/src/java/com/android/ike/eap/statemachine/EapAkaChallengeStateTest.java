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
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EMSK;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.MSK;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AUTN_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AUTS_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.MAC_BYTES;
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

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
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

    private static final byte[] IK = hexStringToByteArray("00112233445566778899AABBCCDDEEFF");
    private static final byte[] CK = hexStringToByteArray("FFEEDDCCBBAA99887766554433221100");

    @Before
    public void setUp() {
        super.setUp();

        mChallengeState = mEapAkaMethodStateMachine.new ChallengeState();
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
        AtMac atMac = new AtMac(MAC_BYTES);

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
        AtMac atMac = new AtMac(MAC_BYTES);

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
        RandChallengeResult result = mChallengeState.new RandChallengeResult(RES_BYTES, IK, CK);
        assertArrayEquals(RES_BYTES, result.res);
        assertArrayEquals(IK, result.ik);
        assertArrayEquals(CK, result.ck);
        assertNull(result.auts);

        result = mChallengeState.new RandChallengeResult(AUTS_BYTES);
        assertArrayEquals(AUTS_BYTES, result.auts);
        assertNull(result.res);
        assertNull(result.ik);
        assertNull(result.ck);

        try {
            mChallengeState.new RandChallengeResult(new byte[0], IK, CK);
            fail("Expected EapSimAkaInvalidLengthException for invalid RES length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }

        try {
            mChallengeState.new RandChallengeResult(RES_BYTES, new byte[0], CK);
            fail("Expected EapSimAkaInvalidLengthException for invalid IK length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }

        try {
            mChallengeState.new RandChallengeResult(RES_BYTES, IK, new byte[0]);
            fail("Expected EapSimAkaInvalidLengthException for invalid CK length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }

        try {
            mChallengeState.new RandChallengeResult(new byte[0]);
            fail("Expected EapSimAkaInvalidLengthException for invalid AUTS length");
        } catch (EapSimAkaInvalidLengthException ex) {
        }
    }
}
