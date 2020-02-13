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

package android.net.ipsec.test.ike;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import android.content.Context;
import android.net.InetAddresses;
import android.net.IpSecManager;
import android.os.Looper;
import android.os.test.TestLooper;
import android.util.Log;

import com.android.internal.net.test.ipsec.ike.IkeSessionStateMachine;
import com.android.internal.net.test.ipsec.ike.IkeSessionStateMachineTest;
import com.android.internal.net.test.ipsec.ike.testutils.MockIpSecTestUtils;

import org.junit.Before;
import org.junit.Test;

import java.net.Inet4Address;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

public final class IkeSessionTest {
    private static final int TIMEOUT_MS = 500;

    private static final Inet4Address LOCAL_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.200"));
    private static final Inet4Address REMOTE_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("127.0.0.1"));

    private MockIpSecTestUtils mMockIpSecTestUtils;
    private IpSecManager mIpSecManager;
    private Context mContext;

    private IkeSessionParams mIkeSessionParams;
    private ChildSessionParams mMockChildSessionParams;
    private Executor mUserCbExecutor;
    private IkeSessionCallback mMockIkeSessionCb;
    private ChildSessionCallback mMockChildSessionCb;

    @Before
    public void setUp() throws Exception {
        if (Looper.myLooper() == null) Looper.prepare();

        mMockIpSecTestUtils = MockIpSecTestUtils.setUpMockIpSec();
        mIpSecManager = mMockIpSecTestUtils.getIpSecManager();
        mContext = mMockIpSecTestUtils.getContext();

        mIkeSessionParams = buildIkeSessionParams();
        mMockChildSessionParams = mock(ChildSessionParams.class);
        mUserCbExecutor = (r) -> r.run(); // Inline executor for testing purposes.
        mMockIkeSessionCb = mock(IkeSessionCallback.class);
        mMockChildSessionCb = mock(ChildSessionCallback.class);
    }

    private IkeSessionParams buildIkeSessionParams() throws Exception {
        return new IkeSessionParams.Builder()
                .setServerAddress(REMOTE_ADDRESS)
                .setUdpEncapsulationSocket(mIpSecManager.openUdpEncapsulationSocket())
                .addSaProposal(IkeSessionStateMachineTest.buildSaProposal())
                .setLocalIdentification(new IkeIpv4AddrIdentification((Inet4Address) LOCAL_ADDRESS))
                .setRemoteIdentification(
                        new IkeIpv4AddrIdentification((Inet4Address) REMOTE_ADDRESS))
                .setAuthPsk(new byte[0] /* psk, unused */)
                .build();
    }

    @Test
    public void testConstructIkeSession() throws Exception {
        IkeSession ikeSession =
                new IkeSession(
                        mContext,
                        mIkeSessionParams,
                        mMockChildSessionParams,
                        mUserCbExecutor,
                        mMockIkeSessionCb,
                        mMockChildSessionCb);
        assertNotNull(ikeSession.mIkeSessionStateMachine.getHandler().getLooper());
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
                                        mIkeSessionParams,
                                        mMockChildSessionParams,
                                        mUserCbExecutor,
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
        assertEquals(
                sessions[0].mIkeSessionStateMachine.getHandler().getLooper(),
                sessions[1].mIkeSessionStateMachine.getHandler().getLooper());
    }

    @Test
    public void testOpensIkeSession() throws Exception {
        TestLooper testLooper = new TestLooper();
        IkeSession ikeSession =
                new IkeSession(
                        testLooper.getLooper(),
                        mContext,
                        mIpSecManager,
                        mIkeSessionParams,
                        mMockChildSessionParams,
                        mUserCbExecutor,
                        mMockIkeSessionCb,
                        mMockChildSessionCb);
        testLooper.dispatchAll();

        assertTrue(
                ikeSession.mIkeSessionStateMachine.getCurrentState()
                        instanceof IkeSessionStateMachine.CreateIkeLocalIkeInit);
    }
}
