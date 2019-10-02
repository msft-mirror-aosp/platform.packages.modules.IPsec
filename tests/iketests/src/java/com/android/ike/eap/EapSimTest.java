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
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_AKA_IDENTITY_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_NAK_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_SUCCESS;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.telephony.TelephonyManager;

import com.android.ike.eap.statemachine.EapStateMachine;

import org.junit.Before;
import org.junit.Test;

/**
 * This test verifies that EAP-SIM is functional for an end-to-end implementation
 */
public class EapSimTest extends EapMethodEndToEndTest {
    private static final long AUTHENTICATOR_TIMEOUT_MILLIS = 250L;

    private static final byte[] NONCE = hexStringToByteArray("37f3ddd3954c4831a5ee08c574844398");
    private static final String UNFORMATTED_IDENTITY = "123456789ABCDEF"; // IMSI

    private static final int SUB_ID = 1;

    // Base 64 of: RAND
    private static final String BASE64_RAND_1 = "EAEjRWeJq83vESNFZ4mrze8=";
    private static final String BASE64_RAND_2 = "EBEjRWeJq83vESNFZ4mrze8=";
    private static final String BASE64_RAND_3 = "ECEjRWeJq83vESNFZ4mrze8=";

    // BASE 64 of: "04" + SRES + "08" + KC
    private static final String BASE64_RESP_1 = "BAq83vAI/ty6mHZUMhA=";
    private static final String BASE64_RESP_2 = "BBq83vEI/ty6mHZUMhE=";
    private static final String BASE64_RESP_3 = "BCq83vII/ty6mHZUMhI=";

    private static final byte[] MSK = hexStringToByteArray(
            "9B1E2B6892BC113F6B6D0B5789DD8ADD"
                    + "B83BE2A84AA50FCAECD0003F92D8DA16"
                    + "4BF983C923695C309F1D7D68DB6992B0"
                    + "76EA8CE7129647A6F198F3A6AA8ADED9");
    private static final byte[] EMSK = hexStringToByteArray(
            "88210b6724400313539c740f417076b0"
                    + "41da7e64658ec365bd2901a7cd7c2763"
                    + "dad1a0508b92a42fdf85ac53c6f7e756"
                    + "7f99b62bcaf467441b567f19b58d86ae");

    private static final byte[] EAP_SIM_START_REQUEST = hexStringToByteArray(
            "01850014120a0000" // EAP header
                    + "0f02000200010000" // AT_VERSION_LIST attribute
                    + "0d010000"); // AT_ANY_ID_REQ attribute
    private static final byte[] EAP_SIM_START_RESPONSE = hexStringToByteArray(
            "02850034120a0000" // EAP header
                    + "0705000037f3ddd3954c4831a5ee08c574844398" // AT_NONCE_MT attribute
                    + "10010001" // AT_SELECTED_VERSION attribute
                    + "0e05001031313233343536373839414243444546"); // AT_IDENTITY attribute
    private static final byte[] EAP_SIM_CHALLENGE_REQUEST = hexStringToByteArray(
            "01860050120b0000" // EAP header
                    + "010d0000" // AT_RAND attribute
                    + "0123456789abcdef1123456789abcdef" // Rand 1
                    + "1123456789abcdef1123456789abcdef" // Rand 2
                    + "2123456789abcdef1123456789abcdef" // Rand 3
                    + "0b050000e4675b17fa7ba4d93db48d1af9ecbb01"); // AT_MAC attribute
    private static final byte[] EAP_SIM_CHALLENGE_RESPONSE = hexStringToByteArray(
            "0286001c120b0000" // EAP header
                    + "0b050000e5df9cb1d935ea5f54d449a038bed061"); // AT_NAC attribute

    private TelephonyManager mMockTelephonyManager;

    @Before
    @Override
    public void setUp() {
        super.setUp();

        mMockTelephonyManager = mock(TelephonyManager.class);

        mEapSessionConfig = new EapSessionConfig.Builder()
                .setEapSimConfig(SUB_ID, APPTYPE_USIM)
                .build();
        mEapAuthenticator =
                new EapAuthenticator(
                        mTestLooper.getLooper(),
                        mMockCallback,
                        new EapStateMachine(mMockContext, mEapSessionConfig, mMockSecureRandom),
                        (runnable) -> runnable.run(),
                        AUTHENTICATOR_TIMEOUT_MILLIS);
    }

    @Test
    public void testEapSimEndToEnd() {
        verifyEapSimStart();
        verifyEapSimChallenge();
        verifyEapSuccess();
    }

    @Test
    public void testEapSimUnsupportedType() {
        // EAP-Request/AKA-Identity (unsupported type)
        mEapAuthenticator.processEapMessage(EAP_REQUEST_AKA_IDENTITY_PACKET);
        mTestLooper.dispatchAll();

        // verify EAP-Response/Nak returned
        verify(mMockCallback).onResponse(eq(EAP_RESPONSE_NAK_PACKET));
        verifyNoMoreInteractions(
                mMockContext,
                mMockTelephonyManager,
                mMockSecureRandom,
                mMockCallback);

        // Switch to EAP-SIM and go through protocol
        verifyEapSimStart();
        verifyEapSimChallenge();
        verifyEapSuccess();
    }

    @Test
    public void verifyEapSimWithEapNotifications() {
        verifyEapNotification(1);
        verifyEapSimStart();

        verifyEapNotification(2);
        verifyEapSimChallenge();

        verifyEapNotification(3);
        verifyEapSuccess();
    }

    private void verifyEapSimStart() {
        // EAP-SIM/Start request
        when(mMockContext.getSystemService(Context.TELEPHONY_SERVICE))
                .thenReturn(mMockTelephonyManager);
        when(mMockTelephonyManager.createForSubscriptionId(SUB_ID))
                .thenReturn(mMockTelephonyManager);
        when(mMockTelephonyManager.getSubscriberId()).thenReturn(UNFORMATTED_IDENTITY);
        doAnswer(invocation -> {
            byte[] dst = invocation.getArgument(0);
            System.arraycopy(NONCE, 0, dst, 0, NONCE.length);
            return null;
        }).when(mMockSecureRandom).nextBytes(eq(new byte[NONCE.length]));

        mEapAuthenticator.processEapMessage(EAP_SIM_START_REQUEST);
        mTestLooper.dispatchAll();
        verify(mMockContext).getSystemService(eq(Context.TELEPHONY_SERVICE));
        verify(mMockTelephonyManager).createForSubscriptionId(SUB_ID);
        verify(mMockTelephonyManager).getSubscriberId();
        verify(mMockSecureRandom).nextBytes(any(byte[].class));

        // verify EAP-SIM/Start response
        verify(mMockCallback).onResponse(eq(EAP_SIM_START_RESPONSE));
        verifyNoMoreInteractions(
                mMockContext,
                mMockTelephonyManager,
                mMockSecureRandom,
                mMockCallback);
    }

    private void verifyEapSimChallenge() {
        // EAP-SIM/Challenge request
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_SIM,
                        BASE64_RAND_1))
                .thenReturn(BASE64_RESP_1);
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_SIM,
                        BASE64_RAND_2))
                .thenReturn(BASE64_RESP_2);
        when(mMockTelephonyManager
                .getIccAuthentication(
                        TelephonyManager.APPTYPE_USIM,
                        TelephonyManager.AUTHTYPE_EAP_SIM,
                        BASE64_RAND_3))
                .thenReturn(BASE64_RESP_3);

        mEapAuthenticator.processEapMessage(EAP_SIM_CHALLENGE_REQUEST);
        mTestLooper.dispatchAll();

        // verify EAP-SIM/Challenge response
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        eq(TelephonyManager.APPTYPE_USIM),
                        eq(TelephonyManager.AUTHTYPE_EAP_SIM),
                        eq(BASE64_RAND_1));
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        eq(TelephonyManager.APPTYPE_USIM),
                        eq(TelephonyManager.AUTHTYPE_EAP_SIM),
                        eq(BASE64_RAND_2));
        verify(mMockTelephonyManager)
                .getIccAuthentication(
                        eq(TelephonyManager.APPTYPE_USIM),
                        eq(TelephonyManager.AUTHTYPE_EAP_SIM),
                        eq(BASE64_RAND_3));
        verify(mMockCallback).onResponse(eq(EAP_SIM_CHALLENGE_RESPONSE));
        verifyNoMoreInteractions(
                mMockContext,
                mMockTelephonyManager,
                mMockSecureRandom,
                mMockCallback);
    }

    private void verifyEapSuccess() {
        // EAP-Success
        mEapAuthenticator.processEapMessage(EAP_SUCCESS);
        mTestLooper.dispatchAll();

        // verify that onSuccess callback made
        verify(mMockCallback).onSuccess(eq(MSK), eq(EMSK));
        verifyNoMoreInteractions(
                mMockContext,
                mMockTelephonyManager,
                mMockSecureRandom,
                mMockCallback);
    }
}
