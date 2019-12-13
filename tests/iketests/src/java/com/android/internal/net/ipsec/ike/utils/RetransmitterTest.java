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

package com.android.internal.net.ipsec.ike.utils;

import static com.android.internal.net.ipsec.ike.IkeSessionStateMachine.CMD_RETRANSMIT;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import android.os.Handler;
import android.os.Message;

import com.android.internal.net.ipsec.ike.message.IkeMessage;

import org.junit.Before;
import org.junit.Test;

public final class RetransmitterTest {
    private Handler mMockHandler;
    private IkeMessage mMockIkeMessage;
    private TestRetransmitter mRetransmitter;

    private class TestRetransmitter extends Retransmitter {
        int mSendCallCount; // Defaults to 0
        boolean mFailed; // Defaults to false

        TestRetransmitter(Handler handler, IkeMessage message) {
            super(handler, message);
        }

        @Override
        public void send(IkeMessage msg) {
            mSendCallCount++;
        }

        @Override
        public void handleRetransmissionFailure() {
            mFailed = true;
        }
    }

    @Before
    public void setUp() throws Exception {
        mMockHandler = mock(Handler.class);
        doReturn(mock(Message.class))
                .when(mMockHandler)
                .obtainMessage(eq(CMD_RETRANSMIT), anyObject());

        mMockIkeMessage = mock(IkeMessage.class);
        mRetransmitter = new TestRetransmitter(mMockHandler, mMockIkeMessage);
    }

    @Test
    public void testSendRequestAndQueueRetransmit() throws Exception {
        mRetransmitter.retransmit();
        assertEquals(1, mRetransmitter.mSendCallCount);
        verify(mMockHandler).obtainMessage(eq(CMD_RETRANSMIT), eq(mRetransmitter));
        verify(mMockHandler)
                .sendMessageDelayed(any(Message.class), eq(Retransmitter.RETRANSMIT_TIMEOUT_MS));
    }

    @Test
    public void testRetransmitQueuesExponentialRetransmit() throws Exception {
        mRetransmitter.retransmit();

        for (int i = 0; i <= Retransmitter.RETRANSMIT_MAX_ATTEMPTS; i++) {
            long expectedTimeout =
                    (long)
                            (Retransmitter.RETRANSMIT_TIMEOUT_MS
                                    * Math.pow(Retransmitter.RETRANSMIT_BACKOFF_FACTOR, i));

            assertEquals(i + 1, mRetransmitter.mSendCallCount);
            assertFalse(mRetransmitter.mFailed);

            // This call happens with the same arguments each time
            verify(mMockHandler, times(i + 1))
                    .obtainMessage(eq(CMD_RETRANSMIT), eq(mRetransmitter));

            // But the expected timeout changes every time
            verify(mMockHandler).sendMessageDelayed(any(Message.class), eq(expectedTimeout));

            verifyNoMoreInteractions(mMockHandler);

            // Trigger next round of retransmissions.
            mRetransmitter.retransmit();
        }
    }

    @Test
    public void testRetransmitterCallsRetranmissionsFailedOnMaxTries() throws Exception {
        mRetransmitter.retransmit();

        // Exhaust all retransmit attempts
        for (int i = 0; i <= Retransmitter.RETRANSMIT_MAX_ATTEMPTS; i++) {
            mRetransmitter.retransmit();
        }

        assertTrue(mRetransmitter.mFailed);
    }

    @Test
    public void testRetransmitterStopsRetransmitting() throws Exception {
        mRetransmitter.stopRetransmitting();

        verify(mMockHandler).removeMessages(eq(CMD_RETRANSMIT), eq(mRetransmitter));
    }
}
