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

import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_REQUEST_NOTIFICATION_PACKET;
import static com.android.ike.eap.message.EapTestMessageDefinitions.EAP_RESPONSE_NOTIFICATION_PACKET;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import android.content.Context;
import android.os.test.TestLooper;

import org.junit.Before;

import java.security.SecureRandom;

public class EapMethodEndToEndTest {
    protected Context mMockContext;
    protected SecureRandom mMockSecureRandom;
    protected IEapCallback mMockCallback;

    protected TestLooper mTestLooper;
    protected EapSessionConfig mEapSessionConfig;
    protected EapAuthenticator mEapAuthenticator;

    @Before
    public void setUp() {
        mMockContext = mock(Context.class);
        mMockSecureRandom = mock(SecureRandom.class);
        mMockCallback = mock(IEapCallback.class);

        mTestLooper = new TestLooper();
    }

    protected void verifyEapNotification(int callsToVerify) {
        mEapAuthenticator.processEapMessage(EAP_REQUEST_NOTIFICATION_PACKET);
        mTestLooper.dispatchAll();

        verify(mMockCallback, times(callsToVerify))
                .onResponse(eq(EAP_RESPONSE_NOTIFICATION_PACKET));
        verifyNoMoreInteractions(mMockCallback);
    }
}
