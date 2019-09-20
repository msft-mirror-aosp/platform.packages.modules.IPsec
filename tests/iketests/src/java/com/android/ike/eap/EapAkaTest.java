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

package com.android.ike.eap;

import static android.telephony.TelephonyManager.APPTYPE_USIM;

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_NOTIFICATION_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_SIM_START_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_NOTIFICATION_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SUCCESS;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.os.test.TestLooper;
import android.telephony.TelephonyManager;

import com.android.ike.eap.statemachine.EapStateMachine;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

/**
 * This test verifies that EAP-AKA is functional for an end-to-end implementation
 */
public class EapAkaTest {
    private static final long AUTHENTICATOR_TIMEOUT_MILLIS = 250L;

    private static final int SUB_ID = 1;
    private static final String UNFORMATTED_IDENTITY = "123456789ABCDEF"; // IMSI

    // TODO(b/140797965): find valid AUTN/RAND values for the CTS test sim
    // IK: 7320EE404E055EF2B5AB0F86E96C48BE
    // CK: E9D1707652E13BF3E05975F601678E5C
    // MK: 2AE8AD50432246E6ACED9AA0FC794A22CE9CE4BB
    // K_encr: DB6F06910D5D19CC9DA5F2687F5C5737
    // K_aut: B20A586592796E08E7408FB53356E9B1
    private static final String RAND_1 = "D6A296F030A305601B311D38A004505C";
    private static final String RAND_2 = "000102030405060708090A0B0C0D0E0F";
    private static final String AUTN = "35A9143ED9E100011795E785DAFAAD9B";
    private static final String RES = "E5167A255FDCDE9248AF6B50ADA0D944";
    private static final String AUTS = "0102030405060708090A0B0C0D0E";
    private static final byte[] MSK =
            hexStringToByteArray(
                    "EFC4FB9F54D99A3F4A04B756993CA813"
                            + "E463CA0ADBF3CB2A296519ED4C600FF5"
                            + "81898B1C425C20FE7471FC43A4BB3C00"
                            + "DDF80A7083972B660BC7153CBF2C9AA1");
    private static final byte[] EMSK =
            hexStringToByteArray(
                    "5C95F3E2476ED4D6588CE6DE2618D808"
                            + "9ECA12A4636C8A1B0C678562CBFC31D3"
                            + "94B578DE0A3686E17F96F14D5341FE75"
                            + "2012944CA394E5288BA1B2C70CB65063");

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

    private static final String REQUEST_MAC = "90C3554783D49A18F9EAA231F3C261EC";
    private static final String RESPONSE_MAC = "D085987D3D15FA50A80D0CECFA2412EB";

    private static final byte[] EAP_AKA_IDENTITY_REQUEST =
            hexStringToByteArray(
                    "01CD000C" // EAP-Request | ID | length in bytes
                            + "17050000" // EAP-AKA | Identity | 2B padding
                            + "0D010000"); // AT_ANY_ID_REQ attribute
    private static final byte[] EAP_AKA_IDENTITY_RESPONSE =
            hexStringToByteArray(
                    "02CD001C" // EAP-Response | ID | length in bytes
                            + "17050000" // EAP-AKA | Identity | 2B padding
                            + "0E05001030313233343536373839414243444546"); // AT_IDENTITY attribute

    private static final byte[] EAP_AKA_CHALLENGE_REQUEST =
            hexStringToByteArray(
                    "01CE0044" // EAP-Request | ID | length in bytes
                            + "17010000" // EAP-AKA | Challenge | 2B padding
                            + "01050000" + RAND_1 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "0B050000" + REQUEST_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_CHALLENGE_RESPONSE =
            hexStringToByteArray(
                    "02CE0030" // EAP-Response | ID | length in bytes
                            + "17010000" // EAP-AKA | Challenge | 2B padding
                            + "03050080" + RES // AT_RES attribute
                            + "0B050000" + RESPONSE_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_CHALLENGE_REQUEST_SYNC_FAIL =
            hexStringToByteArray(
                    "01CE0044" // EAP-Request | ID | length in bytes
                            + "17010000" // EAP-AKA | Challenge | 2B padding
                            + "01050000" + RAND_2 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "0B050000" + REQUEST_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_SYNC_FAIL_RESPONSE =
            hexStringToByteArray(
                    "02CE0018" // EAP-Response | ID | length in bytes
                            + "17040000" // EAP-AKA | Challenge | 2B padding
                            + "0404" + AUTS);  // AT_AUTS attribute
    private static final byte[] EAP_RESPONSE_NAK_PACKET =
            hexStringToByteArray("021000060317"); // NAK with EAP-AKA listed

    private Context mMockContext;
    private TelephonyManager mMockTelephonyManager;
    private SecureRandom mMockSecureRandom;
    private IEapCallback mMockCallback;

    private TestLooper mTestLooper;
    private EapSessionConfig mEapSessionConfig;
    private EapAuthenticator mEapAuthenticator;

    @Before
    public void setUp() {
        mMockContext = mock(Context.class);
        mMockTelephonyManager = mock(TelephonyManager.class);
        mMockSecureRandom = mock(SecureRandom.class);
        mMockCallback = mock(IEapCallback.class);

        mTestLooper = new TestLooper();
        mEapSessionConfig =
                new EapSessionConfig.Builder().setEapAkaConfig(SUB_ID, APPTYPE_USIM).build();
        mEapAuthenticator =
                new EapAuthenticator(
                        mTestLooper.getLooper(),
                        mMockCallback,
                        new EapStateMachine(mMockContext, mEapSessionConfig, mMockSecureRandom),
                        (runnable) -> runnable.run(),
                        AUTHENTICATOR_TIMEOUT_MILLIS);

        when(mMockContext.getSystemService(Context.TELEPHONY_SERVICE))
                .thenReturn(mMockTelephonyManager);
        when(mMockTelephonyManager.createForSubscriptionId(SUB_ID))
                .thenReturn(mMockTelephonyManager);
    }

    @Test
    public void testEapAkaEndToEnd() {
        verifyEapAkaIdentity();
        verifyEapAkaChallenge();
        verifyEapSuccess();
    }

    @Test
    public void testEapAkaWithEapNotifications() {
        verifyEapNotification(1);
        verifyEapAkaIdentity();

        verifyEapNotification(2);
        verifyEapAkaChallenge();

        verifyEapNotification(3);
        verifyEapSuccess();
    }

    @Test
    public void testEapAkaUnsupportedType() {
        // EAP-Request/SIM/Start (unsupported type)
        mEapAuthenticator.processEapMessage(EAP_REQUEST_SIM_START_PACKET);
        mTestLooper.dispatchAll();

        // verify EAP-Response/Nak returned
        verify(mMockCallback).onResponse(eq(EAP_RESPONSE_NAK_PACKET));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);

        verifyEapAkaIdentity();
        verifyEapAkaChallenge();
        verifyEapSuccess();
    }

    @Test
    public void testEapAkaSynchronizationFailure() {
        verifyEapAkaIdentity();
        verifyEapAkaSynchronizationFailure();
        verifyEapAkaChallenge();
        verifyEapSuccess();
    }

    private void verifyEapAkaIdentity() {
        // EAP-AKA/Identity request
        when(mMockTelephonyManager.getSubscriberId()).thenReturn(UNFORMATTED_IDENTITY);

        mEapAuthenticator.processEapMessage(EAP_AKA_IDENTITY_REQUEST);
        mTestLooper.dispatchAll();

        // verify EAP-AKA/Identity response
        verify(mMockContext).getSystemService(eq(Context.TELEPHONY_SERVICE));
        verify(mMockTelephonyManager).createForSubscriptionId(SUB_ID);
        verify(mMockTelephonyManager).getSubscriberId();
        verify(mMockCallback).onResponse(eq(EAP_AKA_IDENTITY_RESPONSE));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapAkaChallenge() {
        // EAP-AKA/Challenge request
        when(mMockTelephonyManager.getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE64_CHALLENGE_1))
                .thenReturn(BASE_64_RESPONSE_SUCCESS);

        mEapAuthenticator.processEapMessage(EAP_AKA_CHALLENGE_REQUEST);
        mTestLooper.dispatchAll();

        // verify EAP-AKA/Challenge response
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE64_CHALLENGE_1);
        verify(mMockCallback).onResponse(eq(EAP_AKA_CHALLENGE_RESPONSE));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapAkaSynchronizationFailure() {
        // EAP-AKA/Challenge request
        when(mMockTelephonyManager.getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE64_CHALLENGE_2))
                .thenReturn(BASE_64_RESPONSE_SYNC_FAIL);

        mEapAuthenticator.processEapMessage(EAP_AKA_CHALLENGE_REQUEST_SYNC_FAIL);
        mTestLooper.dispatchAll();

        // verify EAP-AKA/Synchronization-Failure response
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_AKA,
                        BASE64_CHALLENGE_2);
        verify(mMockCallback).onResponse(eq(EAP_AKA_SYNC_FAIL_RESPONSE));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapSuccess() {
        // EAP-Success
        mEapAuthenticator.processEapMessage(EAP_SUCCESS);
        mTestLooper.dispatchAll();

        // verify that onSuccess callback made
        verify(mMockCallback).onSuccess(eq(MSK), eq(EMSK));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }

    private void verifyEapNotification(int callsToVerify) {
        mEapAuthenticator.processEapMessage(EAP_REQUEST_NOTIFICATION_PACKET);
        mTestLooper.dispatchAll();

        verify(mMockCallback, times(callsToVerify))
                .onResponse(eq(EAP_RESPONSE_NOTIFICATION_PACKET));
        verifyNoMoreInteractions(
                mMockContext, mMockTelephonyManager, mMockSecureRandom, mMockCallback);
    }
}
