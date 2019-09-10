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
    private static final String UNFORMATTED_IDENTITY = "123456789012345"; // IMSI

    // TODO(b/140258387): replace with externally generated values
    // TODO(b/140797965): find valid AUTN/RAND values for the CTS test sim
    // IK: 0123456789ABCDEFFEDCBA9876543210
    // CK: FEDCBA98765432100123456789ABCDEF
    // MK: 342706B4C2632BFD61C3C16675DC3D719DDB7242
    // K_encr: 6ACF941D8E5372A4876427F82BCB7009
    // K_aut: 203FD02EB370465515BC5272E090D178
    private static final String RAND_1 = "00112233445566778899AABBCCDDEEFF";
    private static final String RAND_2 = "000102030405060708090A0B0C0D0E0F";
    private static final String AUTN = "FFEEDDCCBBAA99887766554433221100";
    private static final String RES = "00DEADBEEF";
    private static final String AUTS = "0102030405060708090A0B0C0D0E";
    private static final byte[] MSK =
            hexStringToByteArray(
                    "91844F02FC56EBF0DFCF022224F9599F"
                            + "2D5C66A29002A182AF669C923AA1715C"
                            + "5BC14ABB672373631562E5F8BD494AA8"
                            + "66E54CB0518E95EE98EBA3D88D716C4D");
    private static final byte[] EMSK =
            hexStringToByteArray(
                    "8B04469725F115AA40C3065B3D8B4349"
                            + "18B31CD0C860D77CF42B7E94CE03A96B"
                            + "350511D8F49B0B1305BB693801E62995"
                            + "FAF04D26B49A4BD2587E1661B67B71C6");

    // Base 64 of: [Length][RAND_1][Length][AUTN]
    private static final String BASE64_CHALLENGE_1 =
            "EAARIjNEVWZ3iJmqu8zd7v8Q/+7dzLuqmYh3ZlVEMyIRAA==";

    // Base 64 of: ['DB'][Length][RES][Length][IK][Length][CK]
    private static final String BASE_64_RESPONSE_SUCCESS =
            "2wUA3q2+7xABI0VniavN7/7cuph2VDIQEP7cuph2VDIQASNFZ4mrze8=";

    // Base 64 of: [Length][RAND_2][Length][AUTN]
    private static final String BASE64_CHALLENGE_2 =
            "EAABAgMEBQYHCAkKCwwNDg8Q/+7dzLuqmYh3ZlVEMyIRAA==";

    // Base 64 of: ['DC'][Length][AUTS]
    private static final String BASE_64_RESPONSE_SYNC_FAIL = "3A4BAgMEBQYHCAkKCwwNDg==";

    private static final String REQUEST_MAC = "8BA174E3F5A3F758D027546214744868";
    private static final String RESPONSE_MAC = "5a000bb376b37330f46482c6f6c4e536";

    private static final byte[] EAP_AKA_IDENTITY_REQUEST =
            hexStringToByteArray(
                    "0110000C" // EAP-Request | ID | length in bytes
                            + "17050000" // EAP-AKA | Identity | 2B padding
                            + "0D010000"); // AT_ANY_ID_REQ attribute
    private static final byte[] EAP_AKA_IDENTITY_RESPONSE =
            hexStringToByteArray(
                    "0210001C" // EAP-Response | ID | length in bytes
                            + "17050000" // EAP-AKA | Identity | 2B padding
                            + "0E05001030313233343536373839303132333435"); // AT_IDENTITY attribute

    private static final byte[] EAP_AKA_CHALLENGE_REQUEST =
            hexStringToByteArray(
                    "01110044" // EAP-Request | ID | length in bytes
                            + "17010000" // EAP-AKA | Challenge | 2B padding
                            + "01050000" + RAND_1 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "0B050000" + REQUEST_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_CHALLENGE_RESPONSE =
            hexStringToByteArray(
                    "02110028" // EAP-Response | ID | length in bytes
                            + "17010000" // EAP-AKA | Challenge | 2B padding
                            + "03030028" + RES + "000000" // AT_RES attribute
                            + "0B050000" + RESPONSE_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_CHALLENGE_REQUEST_SYNC_FAIL =
            hexStringToByteArray(
                    "01110044" // EAP-Request | ID | length in bytes
                            + "17010000" // EAP-AKA | Challenge | 2B padding
                            + "01050000" + RAND_2 // AT_RAND attribute
                            + "02050000" + AUTN // AT_AUTN attribute
                            + "0B050000" + REQUEST_MAC); // AT_MAC attribute
    private static final byte[] EAP_AKA_SYNC_FAIL_RESPONSE =
            hexStringToByteArray(
                    "02110018" // EAP-Response | ID | length in bytes
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
