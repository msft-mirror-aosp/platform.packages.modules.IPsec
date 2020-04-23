/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.internal.net.ipsec.ike;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import android.content.Context;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.net.SocketKeepalive;
import android.os.Handler;

import com.android.internal.net.ipsec.ike.testutils.MockIpSecTestUtils;
import com.android.internal.net.ipsec.ike.utils.IkeAlarmReceiver;

import org.junit.Before;

import java.net.Inet4Address;
import java.util.concurrent.Executor;

public abstract class IkeSessionTestBase {
    protected static final Inet4Address LOCAL_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("192.0.2.200"));
    protected static final Inet4Address REMOTE_ADDRESS =
            (Inet4Address) (InetAddresses.parseNumericAddress("127.0.0.1"));
    protected static final String REMOTE_HOSTNAME = "ike.test.android.com";

    protected MockIpSecTestUtils mMockIpSecTestUtils;
    protected Context mSpyContext;
    protected IpSecManager mIpSecManager;

    protected ConnectivityManager mMockConnectManager;
    protected Network mMockDefaultNetwork;
    protected SocketKeepalive mMockSocketKeepalive;

    @Before
    public void setUp() throws Exception {
        mMockIpSecTestUtils = MockIpSecTestUtils.setUpMockIpSec();
        mIpSecManager = mMockIpSecTestUtils.getIpSecManager();

        mSpyContext = spy(mMockIpSecTestUtils.getContext());
        doReturn(null)
                .when(mSpyContext)
                .registerReceiver(
                        any(IkeAlarmReceiver.class),
                        any(IntentFilter.class),
                        any(),
                        any(Handler.class));
        doNothing().when(mSpyContext).unregisterReceiver(any(IkeAlarmReceiver.class));

        mMockConnectManager = mock(ConnectivityManager.class);
        mMockDefaultNetwork = mock(Network.class);
        doReturn(mMockDefaultNetwork).when(mMockConnectManager).getActiveNetwork();
        doReturn(REMOTE_ADDRESS).when(mMockDefaultNetwork).getByName(REMOTE_HOSTNAME);
        doReturn(REMOTE_ADDRESS)
                .when(mMockDefaultNetwork)
                .getByName(REMOTE_ADDRESS.getHostAddress());

        mMockSocketKeepalive = mock(SocketKeepalive.class);
        doReturn(mMockSocketKeepalive)
                .when(mMockConnectManager)
                .createSocketKeepalive(
                        any(Network.class),
                        any(UdpEncapsulationSocket.class),
                        any(Inet4Address.class),
                        any(Inet4Address.class),
                        any(Executor.class),
                        any(SocketKeepalive.Callback.class));
        doReturn(mMockConnectManager)
                .when(mSpyContext)
                .getSystemService(Context.CONNECTIVITY_SERVICE);
    }
}
