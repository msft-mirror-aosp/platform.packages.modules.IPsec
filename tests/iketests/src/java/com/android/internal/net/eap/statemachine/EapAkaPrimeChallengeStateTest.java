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

package com.android.internal.net.eap.statemachine;

import static android.telephony.TelephonyManager.APPTYPE_USIM;

import static com.android.internal.net.TestUtils.hexStringToByteArray;
import static com.android.internal.net.eap.message.EapData.EAP_TYPE_AKA_PRIME;
import static com.android.internal.net.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.CK_BYTES;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_AUTHENTICATION_REJECT;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_IDENTITY_BYTES;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_IDENTITY_RESPONSE;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.IK_BYTES;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.IMSI;
import static com.android.internal.net.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.internal.net.eap.message.simaka.EapAkaTypeData.EAP_AKA_IDENTITY;
import static com.android.internal.net.eap.message.simaka.attributes.EapTestAttributeDefinitions.AUTN_BYTES;
import static com.android.internal.net.eap.message.simaka.attributes.EapTestAttributeDefinitions.MAC_BYTES;
import static com.android.internal.net.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_1_BYTES;
import static com.android.internal.net.eap.message.simaka.attributes.EapTestAttributeDefinitions.RES_BYTES;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import android.net.eap.EapSessionConfig;

import com.android.internal.net.eap.EapResult.EapResponse;
import com.android.internal.net.eap.message.EapData;
import com.android.internal.net.eap.message.EapMessage;
import com.android.internal.net.eap.message.simaka.EapAkaPrimeTypeData;
import com.android.internal.net.eap.message.simaka.EapAkaTypeData;
import com.android.internal.net.eap.message.simaka.EapSimAkaAttribute.AtAnyIdReq;
import com.android.internal.net.eap.message.simaka.EapSimAkaAttribute.AtAutn;
import com.android.internal.net.eap.message.simaka.EapSimAkaAttribute.AtKdf;
import com.android.internal.net.eap.message.simaka.EapSimAkaAttribute.AtKdfInput;
import com.android.internal.net.eap.message.simaka.EapSimAkaAttribute.AtMac;
import com.android.internal.net.eap.message.simaka.EapSimAkaAttribute.AtRandAka;
import com.android.internal.net.eap.message.simaka.EapSimAkaTypeData.DecodeResult;
import com.android.internal.net.eap.statemachine.EapAkaMethodStateMachine.ChallengeState.RandChallengeResult;
import com.android.internal.net.eap.statemachine.EapAkaPrimeMethodStateMachine.ChallengeState;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class EapAkaPrimeChallengeStateTest extends EapAkaPrimeStateTest {
    private static final String SERVER_NETWORK_NAME_STRING = "foo:bar:buzz";
    private static final byte[] SERVER_NETWORK_NAME =
            SERVER_NETWORK_NAME_STRING.getBytes(StandardCharsets.UTF_8);
    private static final String INCORRECT_NETWORK_NAME = "foo:buzz";
    private static final byte[] INCORRECT_SERVER_NETWORK_NAME =
            INCORRECT_NETWORK_NAME.getBytes(StandardCharsets.UTF_8);
    private static final int VALID_KDF = 1;
    private static final int INVALID_KDF = 10;

    private static final byte[] EXPECTED_CK_IK_PRIME =
            hexStringToByteArray(
                    "A0B37E7C7E9CC4F37A5C0AAA55DC87BE51FDA70A9D8F37E62E23B15F1B3941E6");
    private static final byte[] K_ENCR = hexStringToByteArray("15a5bb098528210cde9e8d4a1bd63850");
    private static final byte[] K_AUT =
            hexStringToByteArray(
                    "957b3d518ac9ff028f2cc5177fedad841f5f812cb06e2b88aceaa98129680f35");
    private static final byte[] K_RE =
            hexStringToByteArray(
                    "3c15cf7112935a8170d0904622ecbb67c49dcba5d50814bdd81958e045e42f9c");
    private static final byte[] MSK =
            hexStringToByteArray(
                    "1dcca0351a58d2b858e6cf2380551470d67cc8749d1915409793171abd360118"
                            + "e3ae271bf088ca5a41bb1b9b8f7028bcba888298bfbf64d7b8a4f53a6c2cdf18");
    private static final byte[] EMSK =
            hexStringToByteArray(
                    "a5e6b66a9cb2daa9fe3867d41145848e7bf50d749bfd1bb0d090257402e6a555"
                            + "da6d538e76b71e9f80afe60709965a63a355bdccc4e3a8b358e098e41545fa67");

    private ChallengeState mState;

    @Before
    public void setUp() {
        super.setUp();

        mState = mStateMachine.new ChallengeState();
        mStateMachine.transitionTo(mState);
    }

    @Test
    public void testTransitionWithEapIdentity() throws Exception {
        mStateMachine.transitionTo(mStateMachine.new CreatedState());

        EapData eapData = new EapData(EAP_TYPE_AKA_PRIME, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(new EapAkaPrimeTypeData(EAP_AKA_CHALLENGE, new ArrayList<>()));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));

        mStateMachine.process(eapMessage);

        ChallengeState challengeState = (ChallengeState) mStateMachine.getState();
        assertArrayEquals(EAP_IDENTITY_BYTES, challengeState.mIdentity);

        // decode() is called in CreatedState and ChallengeState
        verify(mMockTypeDataDecoder, times(2)).decode(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testTransitionWithEapAkaPrimeIdentity() throws Exception {
        mStateMachine.transitionTo(mStateMachine.new CreatedState());

        // Process AKA' Identity Request
        EapData eapData = new EapData(EAP_TYPE_AKA_PRIME, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaPrimeTypeData(EAP_AKA_IDENTITY, Arrays.asList(new AtAnyIdReq())));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
        doReturn(IMSI).when(mMockTelephonyManager).getSubscriberId();

        EapResponse eapResponse = (EapResponse) mStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_PRIME_IDENTITY_RESPONSE, eapResponse.packet);

        // decode() is called in CreatedState and IdentityState
        verify(mMockTypeDataDecoder, times(2)).decode(eq(DUMMY_EAP_TYPE_DATA));
        verify(mMockTelephonyManager).getSubscriberId();

        // Process AKA' Challenge Request
        decodeResult =
                new DecodeResult<>(new EapAkaPrimeTypeData(EAP_AKA_CHALLENGE, new ArrayList<>()));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));

        mStateMachine.process(eapMessage);

        ChallengeState challengeState = (ChallengeState) mStateMachine.getState();
        assertArrayEquals(EAP_AKA_PRIME_IDENTITY_BYTES, challengeState.mIdentity);

        // decode() called again in IdentityState and ChallengeState
        verify(mMockTypeDataDecoder, times(4)).decode(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testProcessMissingAtKdf() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA_PRIME, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(MAC_BYTES);
        AtKdfInput atKdfInput = new AtKdfInput(0, SERVER_NETWORK_NAME);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaPrimeTypeData(
                                EAP_AKA_CHALLENGE,
                                Arrays.asList(atRandAka, atAutn, atMac, atKdfInput)));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));

        EapResponse eapResponse = (EapResponse) mStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_PRIME_AUTHENTICATION_REJECT, eapResponse.packet);
        verify(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testProcessMissingAtKdfInput() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA_PRIME, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(MAC_BYTES);
        AtKdf atKdf = new AtKdf(VALID_KDF);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaPrimeTypeData(
                                EAP_AKA_CHALLENGE, Arrays.asList(atRandAka, atAutn, atMac, atKdf)));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));

        EapResponse eapResponse = (EapResponse) mStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_PRIME_AUTHENTICATION_REJECT, eapResponse.packet);
        verify(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testProcessUnsupportedKdf() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA_PRIME, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(MAC_BYTES);
        AtKdfInput atKdfInput = new AtKdfInput(0, SERVER_NETWORK_NAME);
        AtKdf atKdf = new AtKdf(INVALID_KDF);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaPrimeTypeData(
                                EAP_AKA_CHALLENGE,
                                Arrays.asList(atRandAka, atAutn, atMac, atKdfInput, atKdf)));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));

        EapResponse eapResponse = (EapResponse) mStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_PRIME_AUTHENTICATION_REJECT, eapResponse.packet);
        verify(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testProcessIncorrectNetworkName() throws Exception {
        EapData eapData = new EapData(EAP_TYPE_AKA_PRIME, DUMMY_EAP_TYPE_DATA);
        EapMessage eapMessage = new EapMessage(EAP_CODE_REQUEST, ID_INT, eapData);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(MAC_BYTES);
        AtKdfInput atKdfInput = new AtKdfInput(0, INCORRECT_SERVER_NETWORK_NAME);
        AtKdf atKdf = new AtKdf(VALID_KDF);

        DecodeResult<EapAkaTypeData> decodeResult =
                new DecodeResult<>(
                        new EapAkaPrimeTypeData(
                                EAP_AKA_CHALLENGE,
                                Arrays.asList(atRandAka, atAutn, atMac, atKdfInput, atKdf)));
        doReturn(decodeResult).when(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));

        EapResponse eapResponse = (EapResponse) mStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_PRIME_AUTHENTICATION_REJECT, eapResponse.packet);
        verify(mMockTypeDataDecoder).decode(eq(DUMMY_EAP_TYPE_DATA));
    }

    @Test
    public void testProcessIncorrectNetworkNameIsIgnored() throws Exception {
        // Create state machine with configs allowing invalid network name to be ignored
        mStateMachine =
                new EapAkaPrimeMethodStateMachine(
                        mMockContext,
                        EAP_IDENTITY_BYTES,
                        new EapSessionConfig.EapAkaPrimeConfig(
                                SUB_ID, APPTYPE_USIM, PEER_NETWORK_NAME, true),
                        mMockTypeDataDecoder);
        mState = mStateMachine.new ChallengeState();
        mStateMachine.transitionTo(mState);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(MAC_BYTES);
        AtKdfInput atKdfInput = new AtKdfInput(0, INCORRECT_SERVER_NETWORK_NAME);
        AtKdf atKdf = new AtKdf(VALID_KDF);

        EapAkaPrimeTypeData eapAkaPrimeTypeData =
                new EapAkaPrimeTypeData(
                        EAP_AKA_CHALLENGE,
                        Arrays.asList(atRandAka, atAutn, atMac, atKdfInput, atKdf));
        assertTrue(
                "Incorrect network names should be ignored",
                mState.isValidChallengeAttributes(eapAkaPrimeTypeData));
    }

    @Test
    public void testHasMatchingNetworkNames() {
        // "" should match anything
        assertTrue(mState.hasMatchingNetworkNames("", SERVER_NETWORK_NAME_STRING));
        assertTrue(mState.hasMatchingNetworkNames(SERVER_NETWORK_NAME_STRING, ""));

        // "foo:bar" should match "foo:bar:buzz"
        assertTrue(mState.hasMatchingNetworkNames(PEER_NETWORK_NAME, SERVER_NETWORK_NAME_STRING));
        assertTrue(mState.hasMatchingNetworkNames(SERVER_NETWORK_NAME_STRING, PEER_NETWORK_NAME));

        // "foo:buzz" shouldn't match "foo:bar:buzz"
        assertFalse(
                mState.hasMatchingNetworkNames(SERVER_NETWORK_NAME_STRING, INCORRECT_NETWORK_NAME));
        assertFalse(
                mState.hasMatchingNetworkNames(INCORRECT_NETWORK_NAME, SERVER_NETWORK_NAME_STRING));
    }

    @Test
    public void testDeriveCkIkPrime() throws Exception {
        RandChallengeResult randChallengeResult =
                mState.new RandChallengeResult(RES_BYTES, IK_BYTES, CK_BYTES);
        AtKdfInput atKdfInput =
                new AtKdfInput(0, PEER_NETWORK_NAME.getBytes(StandardCharsets.UTF_8));
        AtAutn atAutn = new AtAutn(AUTN_BYTES);

        // S = FC | Network Name | len(Network Name) | SQN ^ AK | len(SQN ^ AK)
        //   = 20666F6F3A62617200070123456789AB0006
        // K = CK | IK
        //   = FFEEDDCCBBAA9988776655443322110000112233445566778899AABBCCDDEEFF
        // CK' | IK' = HMAC-SHA256(K, S)
        //           = A0B37E7C7E9CC4F37A5C0AAA55DC87BE51FDA70A9D8F37E62E23B15F1B3941E6
        byte[] result = mState.deriveCkIkPrime(randChallengeResult, atKdfInput, atAutn);
        assertArrayEquals(EXPECTED_CK_IK_PRIME, result);
    }

    @Test
    public void testGenerateAndPersistEapAkaKeys() throws Exception {
        RandChallengeResult randChallengeResult =
                mState.new RandChallengeResult(RES_BYTES, IK_BYTES, CK_BYTES);

        AtRandAka atRandAka = new AtRandAka(RAND_1_BYTES);
        AtAutn atAutn = new AtAutn(AUTN_BYTES);
        AtMac atMac = new AtMac(MAC_BYTES);
        AtKdfInput atKdfInput =
                new AtKdfInput(0, PEER_NETWORK_NAME.getBytes(StandardCharsets.UTF_8));
        AtKdf atKdf = new AtKdf(VALID_KDF);

        EapAkaPrimeTypeData eapAkaPrimeTypeData =
                new EapAkaPrimeTypeData(
                        EAP_AKA_CHALLENGE,
                        Arrays.asList(atRandAka, atAutn, atMac, atKdfInput, atKdf));

        // CK' | IK' = A0B37E7C7E9CC4F37A5C0AAA55DC87BE51FDA70A9D8F37E62E23B15F1B3941E6
        // data = "EAP-AKA'" | Identity
        //      = 4541502D414B41277465737440616E64726F69642E6E6574
        // prf+(CK' | IK', data) = T1 | T2 | T3 | T4 | T5 | T6 | T7
        // T1 = 15a5bb098528210cde9e8d4a1bd63850957b3d518ac9ff028f2cc5177fedad84
        // T2 = 1f5f812cb06e2b88aceaa98129680f353c15cf7112935a8170d0904622ecbb67
        // T3 = c49dcba5d50814bdd81958e045e42f9c1dcca0351a58d2b858e6cf2380551470
        // T4 = d67cc8749d1915409793171abd360118e3ae271bf088ca5a41bb1b9b8f7028bc
        // T5 = ba888298bfbf64d7b8a4f53a6c2cdf18a5e6b66a9cb2daa9fe3867d41145848e
        // T6 = 7bf50d749bfd1bb0d090257402e6a555da6d538e76b71e9f80afe60709965a63
        // T7 = a355bdccc4e3a8b358e098e41545fa677897d8341c4a107a2343f393ec966181
        // K_encr | K_aut | K_re | MSK | EMSK = prf+(CK' | IK', data)
        assertNull(
                mState.generateAndPersistEapAkaKeys(randChallengeResult, 0, eapAkaPrimeTypeData));
        assertArrayEquals(K_ENCR, mStateMachine.mKEncr);
        assertArrayEquals(K_AUT, mStateMachine.mKAut);
        assertArrayEquals(K_RE, mStateMachine.mKRe);
        assertArrayEquals(MSK, mStateMachine.mMsk);
        assertArrayEquals(EMSK, mStateMachine.mEmsk);
    }
}
