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

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA_PRIME;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_IDENTITY_BYTES;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_AKA_PRIME_IDENTITY_RESPONSE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.ID_INT;
import static com.android.ike.eap.message.EapTestMessageDefinitions.IMSI;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_CHALLENGE;
import static com.android.ike.eap.message.simaka.EapAkaTypeData.EAP_AKA_IDENTITY;

import static org.junit.Assert.assertArrayEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapAkaPrimeTypeData;
import com.android.ike.eap.message.simaka.EapAkaTypeData;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtAnyIdReq;
import com.android.ike.eap.message.simaka.EapSimAkaTypeData.DecodeResult;
import com.android.ike.eap.statemachine.EapAkaPrimeMethodStateMachine.ChallengeState;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;

public class EapAkaPrimeChallengeStateTest extends EapAkaPrimeStateTest {
    @Before
    public void setUp() {
        super.setUp();

        mStateMachine.transitionTo(mStateMachine.new ChallengeState());
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
}
