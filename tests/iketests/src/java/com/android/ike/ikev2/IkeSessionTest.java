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

package com.android.ike.ikev2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import android.content.Context;
import android.net.IpSecManager;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

public final class IkeSessionTest {
    private static final int TIMEOUT_MS = 100;

    private MockIpSecTestUtils mMockIpSecTestUtils;
    private IpSecManager mIpSecManager;
    private Context mContext;

    private IkeSessionOptions mMockIkeSessionOptions;
    private ChildSessionOptions mMockChildSessionOptions;
    private Executor mMockExecutor;
    private IIkeSessionCallback mMockIkeSessionCb;
    private IChildSessionCallback mMockChildSessionCb;

    @Before
    public void setUp() throws Exception {
        mMockIpSecTestUtils = MockIpSecTestUtils.setUpMockIpSec();
        mIpSecManager = mMockIpSecTestUtils.getIpSecManager();
        mContext = mMockIpSecTestUtils.getContext();

        mMockIkeSessionOptions = mock(IkeSessionOptions.class);
        mMockChildSessionOptions = mock(ChildSessionOptions.class);
        mMockExecutor = mock(Executor.class);
        mMockIkeSessionCb = mock(IIkeSessionCallback.class);
        mMockChildSessionCb = mock(IChildSessionCallback.class);
    }

    @Test
    public void testConstructIkeSession() throws Exception {
        IkeSession ikeSession =
                new IkeSession(
                        mContext,
                        mMockIkeSessionOptions,
                        mMockChildSessionOptions,
                        mMockExecutor,
                        mMockIkeSessionCb,
                        mMockChildSessionCb);
        assertNotNull(ikeSession.getHandler().getLooper());
    }

    /**
     * Test that when users construct IkeSessions from different threads, these IkeSessions will
     * still be running on the same IKE worker thread.
     */
    @Test
    public void testConstructFromDifferentThreads() throws Exception {
        final int numSession = 2;
        IkeSession[] sessions = new IkeSession[numSession];

        final CountDownLatch cntLatch = new CountDownLatch(2);

        for (int i = 0; i < numSession; i++) {
            int index = i;
            new Thread() {
                @Override
                public void run() {
                    try {
                        sessions[index] =
                                new IkeSession(
                                        mContext,
                                        mMockIkeSessionOptions,
                                        mMockChildSessionOptions,
                                        mMockExecutor,
                                        mMockIkeSessionCb,
                                        mMockChildSessionCb);
                        cntLatch.countDown();
                    } catch (Exception e) {
                        Log.e("IkeSessionTest", "error encountered constructing IkeSession. ", e);
                    }
                }
            }.start();
        }

        assertTrue(cntLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));

        // Verify that two sessions use the same looper.
        assertEquals(sessions[0].getHandler().getLooper(), sessions[1].getHandler().getLooper());
    }
}
