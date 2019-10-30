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

import static android.telephony.TelephonyManager.APPTYPE_USIM;

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA_PRIME;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_AUTHENTICATION_REJECT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_IDENTITY_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_IDENTITY_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.IMSI;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_IDENTITY;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AUTN_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.MAC_BYTES;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_1_BYTES;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapSessionConfig;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapAkaPrimeTypeData;
import com.android.ike.eap.message.simaka.EapAkaTypeData;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtAnyIdReq;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtAutn;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtKdf;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtKdfInput;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtMac;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtRandAka;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData.DecodeResult;
import com.android.ike.eap.statemachine.EapAkaPrimeMethodStateMachine.ChallengeState;

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
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

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
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);
        when(mMockTelephonyManager.getSubscriberId()).thenReturn(IMSI);

        EapResponse eapResponse = (EapResponse) mStateMachine.process(eapMessage);
        assertArrayEquals(EAP_AKA_PRIME_IDENTITY_RESPONSE, eapResponse.packet);

        // decode() is called in CreatedState and IdentityState
        verify(mMockTypeDataDecoder, times(2)).decode(eq(DUMMY_EAP_TYPE_DATA));
        verify(mMockTelephonyManager).getSubscriberId();

        // Process AKA' Challenge Request
        decodeResult =
                new DecodeResult<>(new EapAkaPrimeTypeData(EAP_AKA_CHALLENGE, new ArrayList<>()));
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

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
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

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
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

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
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

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
        when(mMockTypeDataDecoder.decode(eq(DUMMY_EAP_TYPE_DATA))).thenReturn(decodeResult);

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
}
