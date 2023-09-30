/*
 * Copyright (C) 2023 The Android Open Source Project
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import android.net.ipsec.test.ike.IkeSessionCallback;

import com.android.internal.net.ipsec.test.ike.utils.LivenessAssister;

import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.Executor;

public final class LivenessAssisterTest {

    LivenessAssister mLivenessAssister;
    Executor mSpyUserCbExecutor;

    IkeSessionCallback mMockIkeSessionCallback;

    @Before
    public void setUp() throws Exception {
        mMockIkeSessionCallback = mock(IkeSessionCallback.class);
        mSpyUserCbExecutor =
                spy(
                        (command) -> {
                            command.run();
                        });
        mLivenessAssister = new LivenessAssister(mMockIkeSessionCallback, mSpyUserCbExecutor);
    }

    @Test
    public void testLivenessCheckRequestedWithDpdOnDemandIkeLocalInfo() throws Exception {
        assertFalse(mLivenessAssister.isLivenessCheckRequested());
        mLivenessAssister.livenessCheckRequested(LivenessAssister.REQ_TYPE_ON_DEMAND);
        mLivenessAssister.livenessCheckRequested(LivenessAssister.REQ_TYPE_BACKGROUND);
        verify(mSpyUserCbExecutor, times(2)).execute(any(Runnable.class));
        assertTrue(mLivenessAssister.isLivenessCheckRequested());
        verify(mMockIkeSessionCallback)
                .onLivenessStatusChanged(eq(IkeSessionCallback.LIVENESS_STATUS_ON_DEMAND_STARTED));
        verify(mMockIkeSessionCallback)
                .onLivenessStatusChanged(eq(IkeSessionCallback.LIVENESS_STATUS_ON_DEMAND_ONGOING));
    }

    @Test
    public void testLivenessCheckRequestedWithJoiningBusyStateRunningInBackground()
            throws Exception {
        assertFalse(mLivenessAssister.isLivenessCheckRequested());
        mLivenessAssister.livenessCheckRequested(LivenessAssister.REQ_TYPE_BACKGROUND);
        mLivenessAssister.livenessCheckRequested(LivenessAssister.REQ_TYPE_BACKGROUND);
        verify(mSpyUserCbExecutor, times(2)).execute(any(Runnable.class));
        assertTrue(mLivenessAssister.isLivenessCheckRequested());
        verify(mMockIkeSessionCallback)
                .onLivenessStatusChanged(eq(IkeSessionCallback.LIVENESS_STATUS_BACKGROUND_STARTED));
        verify(mMockIkeSessionCallback)
                .onLivenessStatusChanged(eq(IkeSessionCallback.LIVENESS_STATUS_BACKGROUND_ONGOING));
    }

    @Test
    public void testLivenessCheckRequestedAndSuccessCallback() throws Exception {
        mLivenessAssister.livenessCheckRequested(LivenessAssister.REQ_TYPE_ON_DEMAND);
        assertTrue(mLivenessAssister.isLivenessCheckRequested());
        mLivenessAssister.markPeerAsAlive();
        assertFalse(mLivenessAssister.isLivenessCheckRequested());
        verify(mSpyUserCbExecutor, times(2)).execute(any(Runnable.class));
        verify(mMockIkeSessionCallback)
                .onLivenessStatusChanged(eq(IkeSessionCallback.LIVENESS_STATUS_SUCCESS));
    }

    @Test
    public void testLivenessCheckRequestedAndFailureCallback() throws Exception {
        mLivenessAssister.livenessCheckRequested(LivenessAssister.REQ_TYPE_BACKGROUND);
        assertTrue(mLivenessAssister.isLivenessCheckRequested());
        mLivenessAssister.markPeerAsDead();
        assertFalse(mLivenessAssister.isLivenessCheckRequested());
        verify(mSpyUserCbExecutor, times(2)).execute(any(Runnable.class));
        verify(mMockIkeSessionCallback)
                .onLivenessStatusChanged(eq(IkeSessionCallback.LIVENESS_STATUS_FAILURE));
    }
}
