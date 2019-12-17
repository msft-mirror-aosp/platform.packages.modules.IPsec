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

package com.android.internal.net.eap;

import static android.telephony.TelephonyManager.APPTYPE_USIM;

import static com.android.internal.net.TestUtils.hexStringToByteArray;
import static com.android.internal.net.eap.message.EapTestMessageDefinitions.EAP_REQUEST_SIM_START_PACKET;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.eap.EapSessionConfig;
import android.telephony.TelephonyManager;

import com.android.internal.net.eap.statemachine.EapStateMachine;

import org.junit.Before;
import org.junit.Test;

public class EapAkaPrimeTest extends EapMethodEndToEndTest {
    private static final long AUTHENTICATOR_TIMEOUT_MILLIS = 250L;

    private static final int SUB_ID = 1;
    private static final String UNFORMATTED_IDENTITY = "123456789ABCDEF"; // IMSI

    // EAP_IDENTITY = hex("test@android.net")
    private static final byte[] EAP_IDENTITY =
            hexStringToByteArray("7465737440616E64726F69642E6E6574");
    private static final boolean ALLOW_MISMATCHED_NETWORK_NAMES = false;
    private static final String PEER_NETWORK_NAME_1 = "foo:bar";
    private static final String PEER_NETWORK_NAME_2 = "bar";

    // hex("foo:bar:buzz")
    private static final String SERVER_NETWORK_NAME = "666F6F3A6261723A62757A7A";

    // TODO(b/142667016): replace with externally generated test values

    // IK: 7320EE404E055EF2B5AB0F86E96C48BE
    // CK: E9D1707652E13BF3E05975F601678E5C
    // Server Network Name: 666F6F3A6261723A62757A7A
    // SQN ^ AK: 35A9143ED9E1
    // IK': 79DC30692F3D2303D148549E5D50D0AA
    // CK': BBD0A7AD3F14757BA604C4CBE70F9090
    // K_encr: 4c22c289bcf40367cf2bdb6a6e3fe56b
    // K_aut: c64abd508ab628f842e9fb40a14fea769d2ccc67a8412794fe3b4c2556431e78
    // K_re: 5454ccf7ecc227f25c6cd1023e09394fa5cedc14a2f155e9d96a70dc404b4dca
    private static final String RAND_1 = "D6A296F030A305601B311D38A004505C";
    private static final String RAND_2 = "000102030405060708090A0B0C0D0E0F";
    private static final String AUTN = "35A9143ED9E100011795E785DAFAAD9B";
    private static final String RES = "E5167A255FDCDE9248AF6B50ADA0D944";
    private static final String AUTS = "0102030405060708090A0B0C0D0E";
    private static final byte[] MSK =
            hexStringToByteArray(
                    "695788d8f33af56b5b2fea065a0e8656"
                            + "7dc48120d6070d96056f9668614ec3e7"
                            + "feb4933a3aaab3587980a624998c8b5e"
                            + "a69d7295b824ef4a2201720be89d04df");
    private static final byte[] EMSK =
            hexStringToByteArray(
                    "2db1f574d6e92cec294779defef5a7f0"
                            + "49319cc75367102815d0244087f23660"
                            + "0986b47a862c1aeeca418c84a2f9581b"
                            + "0738fdefd229a5f7a4ca76709379bf00");

    // IK: 7320EE404E055EF2B5AB0F86E96C48BE
    // CK: E9D1707652E13BF3E05975F601678E5C
    // Server Network Name: 666F6F3A6261723A62757A7A
    // SQN ^ AK: 35A9143ED9E1
    // IK': 6C45FB0B12FF8172223B6D0E599EAE20
    // CK': A01C894696BEB759ABE0340F71A20D7B
    // K_encr: c039213c78fcf78a34bef30219a77822
    // K_aut: 95b014e569144eba71a387f91fb6b72e06781df12d61bfe88e5149477cd232aa
    // K_re: 1000c2e2f01766a4d2581ac454e41fce1ee17bcccbc32dfad78815075d884c5e
    private static final byte[] MSK_WITHOUT_IDENTITY_REQ =
            hexStringToByteArray(
                    "ad75a86586773134dcd9e78e3f75b282"
                            + "7a42435cb1be7235be58cddc60a0ba19"
                            + "dd5c30accfdb0db5ef065f46c3c25d7b"
                            + "9f8703d9493a2dc6fb6563dbdc854658");
    private static final byte[] EMSK_WITHOUT_IDENTITY_REQ =
            hexStringToByteArray(
                    "31a3f2bb0e3e831d991dc8666438297f"
                            + "4a5bc157fc1e31537e5a4927206d7b4b"
                            + "db830761eea3441d9b90da48aebb9734"
                            + "d3cbdec96072230a64043f54932a8841");

    // Base 64 of: [Length][RAND_1][Length][AUTN]
    private static final String BASE64_CHALLENGE_1 =
            "ENailvAwowVgGzEdOKAEUFwQNakUPtnhAAEXleeF2vqtmw==";

    // Base 64 of: ['DB'][Length][RES][Length][IK][Length][CK]
    private static final String BASE_64_RESPONSE_SUCCESS =
            "2xDlFnolX9zekkiva1CtoNlEEHMg7kBOBV7ytasPhulsSL4Q6dFwdlLhO/PgWXX2AWeOXA==";

    // Base 64 of: [Length][RAND_2][Length][AUTN]
    private static final String BASE64_CHALLENGE_2 =
            "EAABAgMEBQYHCAkKCwwNDg8QNakUPtnhAAEXleeF2vqtmw==";

    // Base 64 of: ['DC'][Length][AUTS]
    private static final String BASE_64_RESPONSE_SYNC_FAIL = "3A4BAgMEBQYHCAkKCwwNDg==";

    private static final String REQUEST_MAC = "9089f89b2f99bb85f2f2b529779f98db";
    private static final String RESPONSE_MAC = "48d7d6a80e1e2ff26a1e4148e0a2303e";
    private static final String REQUEST_MAC_WITHOUT_IDENTITY_REQ =
            "59f680ede020a3d0156eef56affb6997";
    private static final String RESPONSE_MAC_WITHOUT_IDENTITY_REQ =
            "e15322ff4abe51479c0fa92d00e343d7";

    private static final byte[] EAP_AKA_PRIME_IDENTITY_REQUEST =
            hexStringToByteArray(
                    "01CD000C" // EAP-Request | ID | length in bytes
                            + "32050000" // EAP-AKA' | Identity | 2B padding
                            + "0D010000"); // AT_ANY_ID_REQ attribute
    private static final byte[] EAP_AKA_PRIME_IDENTITY_RESPONSE =
            hexStringToByteArray(
                    "02CD001C" // EAP-Response | ID | length in bytes
                            + "32050000" // EAP-AKA' | Identity | 2B padding
                            + "0E05001036313233343536373839414243444546"); // AT_IDENTITY attribute

    private static final byte[] EAP_AKA_PRIME_CHALLENGE_REQUEST =
            hexStringToByteArray(
                    "01CE0044" // EAP-Request | ID | length in bytes
                            + "32010000" // EAP-AKA' | Challenge | 2B padding
                            + "01050000" + RAND_1 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "1704000C" + SERVER_NETWORK_NAME // AT_KDF_INPUT attribute
                            + "18010001" // AT_KDF attribute
                            + "0B050000" + REQUEST_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_PRIME_CHALLENGE_RESPONSE =
            hexStringToByteArray(
                    "02CE0030" // EAP-Response | ID | length in bytes
                            + "32010000" // EAP-AKA' | Challenge | 2B padding
                            + "03050080" + RES // AT_RES attribute
                            + "0B050000" + RESPONSE_MAC); // AT_MAC attribute

    private static final byte[] EAP_AKA_PRIME_CHALLENGE_REQUEST_WITHOUT_IDENTITY_REQ =
            hexStringToByteArray(
                    "01CE0044" // EAP-Request | ID | length in bytes
                            + "32010000" // EAP-AKA' | Challenge | 2B padding
                            + "01050000" + RAND_1 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "1704000C" + SERVER_NETWORK_NAME // AT_KDF_INPUT attribute
                            + "18010001" // AT_KDF attribute
                            + "0B050000" + REQUEST_MAC_WITHOUT_IDENTITY_REQ); // AT_MAC attribute
    private static final byte[] EAP_AKA_PRIME_CHALLENGE_RESPONSE_WITHOUT_IDENTITY_REQUEST =
            hexStringToByteArray(
                    "02CE0030" // EAP-Response | ID | length in bytes
                            + "32010000" // EAP-AKA' | Challenge | 2B padding
                            + "03050080" + RES // AT_RES attribute
                            + "0B050000" + RESPONSE_MAC_WITHOUT_IDENTITY_REQ); // AT_MAC attribute

    private static final byte[] EAP_AKA_PRIME_CHALLENGE_REQUEST_SYNC_FAIL =
            hexStringToByteArray(
                    "01CE0044" // EAP-Request | ID | length in bytes
                            + "32010000" // EAP-AKA' | Challenge | 2B padding
                            + "01050000" + RAND_2 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "1704000C" + SERVER_NETWORK_NAME // AT_KDF_INPUT attribute
                            + "18010001" // AT_KDF attribute
                            + "0B050000" + REQUEST_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_PRIME_SYNC_FAIL_RESPONSE =
            hexStringToByteArray(
                    "02CE0018" // EAP-Response | ID | length in bytes
                            + "32040000" // EAP-AKA' | Synchronization-Failure | 2B padding
                            + "0404" + AUTS);  // AT_AUTS attribute

    private static final byte[] EAP_AKA_PRIME_AUTHENTICATION_REJECT =
            hexStringToByteArray(
                    "02CE0008" // EAP-Response | ID | length in bytes
                            + "32020000"); // EAP-AKA' | Authentication-Reject | 2B padding

    private static final byte[] EAP_RESPONSE_NAK_PACKET =
            hexStringToByteArray("021000060332"); // NAK with EAP-AKA' listed

    private TelephonyManager mMockTelephonyManager;

    @Before
    @Override
    public void setUp() {
        super.setUp();

        setUp(ALLOW_MISMATCHED_NETWORK_NAMES, PEER_NETWORK_NAME_1);
    }

    private void setUp(boolean allowMismatchedNetworkNames, String peerNetworkName) {
        mMockTelephonyManager = mock(TelephonyManager.class);

        mEapSessionConfig =
                new EapSessionConfig.Builder()
                        .setEapIdentity(EAP_IDENTITY)
                        .setEapAkaPrimeConfig(
                                SUB_ID, APPTYPE_USIM, peerNetworkName, allowMismatchedNetworkNames)
                        .build();
        mEapAuthenticator =
                new EapAuthenticator(
                        mTestLooper.getLooper(),
                        mMockCallback,
                        new EapStateMachine(mMockContext, mEapSessionConfig, mMockSecureRandom),
                        (runnable) -> runnable.run(),
                        AUTHENTICATOR_TIMEOUT_MILLIS);

        TelephonyManager mockTelephonyManagerFromContext = mock(TelephonyManager.class);
        doReturn(mockTelephonyManagerFromContext)
                .when(mMockContext)
                .getSystemService(Context.TELEPHONY_SERVICE);
        doReturn(mMockTelephonyManager)
                .when(mockTelephonyManagerFromContext)
                .createForSubscriptionId(SUB_ID);
    }

    @Test
    public void testEapAkaPrimeEndToEnd() {
        verifyEapPrimeAkaIdentity();
        verifyEapAkaPrimeChallenge(BASE_64_RESPONSE_SUCCESS, EAP_AKA_PRIME_CHALLENGE_RESPONSE);
        verifyEapSuccess(MSK, EMSK);
    }

    @Test
    public void testEapAkaPrimeEndToEndWithoutIdentityRequest() {
        verifyEapAkaPrimeChallengeWithoutIdentityReq();
        verifyEapSuccess(MSK_WITHOUT_IDENTITY_REQ, EMSK_WITHOUT_IDENTITY_REQ);
    }

    @Test
    public void testEapAkaPrimeWithEapNotifications() {
        verifyEapNotification(1);
        verifyEapPrimeAkaIdentity();

        verifyEapNotification(2);
        verifyEapAkaPrimeChallenge(BASE_64_RESPONSE_SUCCESS, EAP_AKA_PRIME_CHALLENGE_RESPONSE);

        verifyEapNotification(3);
        verifyEapSuccess(MSK, EMSK);
    }

    @Test
    public void testEapAkaPrimeUnsupportedType() {
        verifyUnsupportedType(EAP_REQUEST_SIM_START_PACKET, EAP_RESPONSE_NAK_PACKET);

        verifyEapPrimeAkaIdentity();
        verifyEapAkaPrimeChallenge(BASE_64_RESPONSE_SUCCESS, EAP_AKA_PRIME_CHALLENGE_RESPONSE);
        verifyEapSuccess(MSK, EMSK);
    }

    @Test
    public void testEapAkaPrimeSynchronizationFailure() {
        verifyEapPrimeAkaIdentity();
        verifyEapAkaPrimeSynchronizationFailure();
        verifyEapAkaPrimeChallenge(BASE_64_RESPONSE_SUCCESS, EAP_AKA_PRIME_CHALLENGE_RESPONSE);
        verifyEapSuccess(MSK, EMSK);
    }

    @Test
    public void testEapAkaPrimeAuthenticationReject() {
        verifyEapPrimeAkaIdentity();

        // return null from TelephonyManager to simluate rejection of AUTN
        verifyEapAkaPrimeChallenge(null, EAP_AKA_PRIME_AUTHENTICATION_REJECT);
        verifyExpectsEapFailure(EAP_AKA_PRIME_CHALLENGE_REQUEST);
        verifyEapFailure();
    }

    @Test
    public void testEapAkaPrimeMismatchedNetworkNamesNotAllowed() {
        // use mismatched peer network name
        setUp(false, PEER_NETWORK_NAME_2);
        verifyEapPrimeAkaIdentity();
        verifyEapAkaPrimeChallengeMismatchedNetworkNames();
        verifyEapFailure();
    }

    @Test
    public void testEapAkaPrimeMismatchedNetworkNamesAllowed() {
        setUp(true, PEER_NETWORK_NAME_2);
        verifyEapPrimeAkaIdentity();
        verifyEapAkaPrimeChallenge(BASE_64_RESPONSE_SUCCESS, EAP_AKA_PRIME_CHALLENGE_RESPONSE);
        verifyEapSuccess(MSK, EMSK);
    }

    private void verifyEapPrimeAkaIdentity() {
        // EAP-AKA'/Identity request
        doReturn(UNFORMATTED_IDENTITY).when(mMockTelephonyManager).getSubscriberId();

        mEapAuthenticator.processEapMessage(EAP_AKA_PRIME_IDENTITY_REQUEST);
        mTestLooper.dispatchAll();

        // verify EAP-AKA'/Identity response
        verify(mMockContext).getSystemService(eq(Context.TELEPHONY_SERVICE));
        verify(mMockTelephonyManager).getSubscriberId();
        verify(mMockCallback).onResponse(eq(EAP_AKA_PRIME_IDENTITY_RESPONSE));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapAkaPrimeChallenge(
            String challengeBase64,
            String responseBase64,
            byte[] incomingEapPacket,
            byte[] outgoingEapPacket) {
        // EAP-AKA'/Challenge request
        when(mMockTelephonyManager.getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        challengeBase64))
                .thenReturn(responseBase64);

        mEapAuthenticator.processEapMessage(incomingEapPacket);
        mTestLooper.dispatchAll();

        // verify EAP-AKA'/Challenge response
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        challengeBase64);
        verify(mMockCallback).onResponse(eq(outgoingEapPacket));
    }

    private void verifyEapAkaPrimeChallenge(String responseBase64, byte[] outgoingPacket) {
        verifyEapAkaPrimeChallenge(
                BASE64_CHALLENGE_1,
                responseBase64,
                EAP_AKA_PRIME_CHALLENGE_REQUEST,
                outgoingPacket);
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapAkaPrimeChallengeWithoutIdentityReq() {
        verifyEapAkaPrimeChallenge(
                BASE64_CHALLENGE_1,
                BASE_64_RESPONSE_SUCCESS,
                EAP_AKA_PRIME_CHALLENGE_REQUEST_WITHOUT_IDENTITY_REQ,
                EAP_AKA_PRIME_CHALLENGE_RESPONSE_WITHOUT_IDENTITY_REQUEST);

        // also need to verify interactions with Context and TelephonyManager
        verify(mMockContext).getSystemService(eq(Context.TELEPHONY_SERVICE));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapAkaPrimeSynchronizationFailure() {
        verifyEapAkaPrimeChallenge(
                BASE64_CHALLENGE_2,
                BASE_64_RESPONSE_SYNC_FAIL,
                EAP_AKA_PRIME_CHALLENGE_REQUEST_SYNC_FAIL,
                EAP_AKA_PRIME_SYNC_FAIL_RESPONSE);
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapAkaPrimeChallengeMismatchedNetworkNames() {
        // EAP-AKA'/Challenge request
        mEapAuthenticator.processEapMessage(EAP_AKA_PRIME_CHALLENGE_REQUEST);
        mTestLooper.dispatchAll();
        verify(mMockCallback).onResponse(eq(EAP_AKA_PRIME_AUTHENTICATION_REJECT));
    }

    @Override
    protected void verifyEapSuccess(byte[] msk, byte[] emsk) {
        super.verifyEapSuccess(msk, emsk);

        verifyNoMoreInteractions(mMockTelephonyManager);
    }
}
