/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.internal.net.ipsec.test.ike.keepalive;

import static android.net.SocketKeepalive.ERROR_INVALID_IP_ADDRESS;
import static android.net.ipsec.test.ike.IkeSessionParams.IKE_OPTION_AUTOMATIC_KEEPALIVE_ON_OFF;

import static com.android.internal.net.ipsec.test.ike.keepalive.IkeNattKeepalive.KeepaliveConfig;
import static com.android.internal.net.ipsec.test.ike.utils.IkeAlarm.IkeAlarmConfig;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

import android.app.PendingIntent;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.SocketKeepalive;
import android.net.ipsec.test.ike.IkeSessionParams;
import android.os.Build;
import android.os.Message;

import com.android.internal.net.ipsec.test.ike.IkeContext;
import com.android.internal.net.ipsec.test.ike.utils.IkeAlarm.IkeAlarmConfig;
import com.android.testutils.DevSdkIgnoreRule;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.net.Inet4Address;
import java.util.concurrent.TimeUnit;

public class IkeNattKeepaliveTest {
    private static final int KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS = 50;

    @Rule
    public final DevSdkIgnoreRule ignoreRule = new DevSdkIgnoreRule();

    private ConnectivityManager mMockConnectManager;
    private IkeSessionParams mMockIkeParams;
    private IkeNattKeepalive.Dependencies mMockDeps;
    private SocketKeepalive mMockSocketKeepalive;
    private SoftwareKeepaliveImpl mMockSoftwareKeepalive;

    private IkeNattKeepalive mIkeNattKeepalive;

    @Before
    public void setUp() throws Exception {
        mMockIkeParams = mock(IkeSessionParams.class);
        doReturn(KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS)
                .when(mMockIkeParams)
                .getNattKeepAliveDelaySeconds();

        mMockConnectManager = mock(ConnectivityManager.class);
        mMockSocketKeepalive = mock(SocketKeepalive.class);
        resetMockConnectManager();

        mMockDeps = mock(IkeNattKeepalive.Dependencies.class);
        mMockSoftwareKeepalive = mock(SoftwareKeepaliveImpl.class);
        resetMockDeps();

        mIkeNattKeepalive =
                createIkeNattKeepalive(
                        mock(IkeContext.class), mMockIkeParams, mock(NetworkCapabilities.class));
    }

    private void resetMockConnectManager() {
        reset(mMockConnectManager);
        doReturn(mMockSocketKeepalive)
                .when(mMockConnectManager)
                .createSocketKeepalive(
                        anyObject(),
                        anyObject(),
                        anyObject(),
                        anyObject(),
                        anyObject(),
                        anyObject());
    }

    private void resetMockDeps() {
        reset(mMockDeps);
        doReturn(mMockSoftwareKeepalive)
                .when(mMockDeps)
                .createSoftwareKeepaliveImpl(anyObject(), anyObject(), anyObject(), anyObject());
    }

    private IkeNattKeepalive createIkeNattKeepalive(
            IkeContext mockIkeContext, IkeSessionParams mockIkeParams, NetworkCapabilities mockNc)
            throws Exception {
        return new IkeNattKeepalive(
                mockIkeContext,
                mMockConnectManager,
                new KeepaliveConfig(
                        mock(Inet4Address.class),
                        mock(Inet4Address.class),
                        mock(UdpEncapsulationSocket.class),
                        mock(Network.class),
                        mock(Network.class),
                        new IkeAlarmConfig(
                                mock(Context.class),
                                "TEST",
                                TimeUnit.SECONDS.toMillis(
                                        KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS),
                                mock(PendingIntent.class),
                                mock(Message.class)),
                        mockIkeParams,
                        mockNc),
                mMockDeps);
    }

    @After
    public void tearDown() throws Exception {
        mIkeNattKeepalive.stop();
    }

    @DevSdkIgnoreRule.IgnoreAfter(Build.VERSION_CODES.TIRAMISU)
    @Test
    public void testStartStopHardwareKeepaliveBeforeU() throws Exception {
        testStartStopHardwareKeepalive(true);
    }

    @DevSdkIgnoreRule.IgnoreUpTo(Build.VERSION_CODES.TIRAMISU)
    @Test
    public void testStartStopHardwareKeepaliveAfterU() throws Exception {
        testStartStopHardwareKeepalive(false);
    }

    private void testStartStopHardwareKeepalive(boolean beforeU) throws Exception {
        mIkeNattKeepalive.start();
        if (beforeU) {
            verify(mMockSocketKeepalive).start(eq(KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS));
        } else {
            // Flag should be 0 if IKE_OPTION_AUTOMATIC_KEEPALIVE_ON_OFF is not set.
            verify(mMockSocketKeepalive).start(eq(KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS),
                    eq(0), any());
        }

        mIkeNattKeepalive.stop();
        verify(mMockSocketKeepalive).stop();
    }

    private IkeNattKeepalive setupKeepaliveWithDisableKeepaliveNoTcpConnectionsOption()
            throws Exception {
        doReturn(true).when(mMockIkeParams)
                .hasIkeOption(IKE_OPTION_AUTOMATIC_KEEPALIVE_ON_OFF);
        return createIkeNattKeepalive(
                mock(IkeContext.class), mMockIkeParams, mock(NetworkCapabilities.class));
    }

    @DevSdkIgnoreRule.IgnoreUpTo(Build.VERSION_CODES.TIRAMISU)
    @Test
    public void testKeepaliveWithDisableKeepaliveNoTcpConnectionsOption() throws Exception {
        final IkeNattKeepalive ikeNattKeepalive =
                setupKeepaliveWithDisableKeepaliveNoTcpConnectionsOption();

        try {
            ikeNattKeepalive.start();
            verify(mMockSocketKeepalive).start(
                    eq(KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS),
                    eq(SocketKeepalive.FLAG_AUTOMATIC_ON_OFF),
                    any());
        } finally {
            ikeNattKeepalive.stop();
        }
    }

    private static SocketKeepalive.Callback verifyHardwareKeepaliveAndGetCb(
            ConnectivityManager mockConnectManager) throws Exception {
        ArgumentCaptor<SocketKeepalive.Callback> socketKeepaliveCbCaptor =
                ArgumentCaptor.forClass(SocketKeepalive.Callback.class);

        verify(mockConnectManager)
                .createSocketKeepalive(
                        anyObject(),
                        anyObject(),
                        anyObject(),
                        anyObject(),
                        anyObject(),
                        socketKeepaliveCbCaptor.capture());

        return socketKeepaliveCbCaptor.getValue();
    }

    @Test
    public void testSwitchToSoftwareKeepalive() throws Exception {
        SocketKeepalive.Callback socketKeepaliveCb =
                verifyHardwareKeepaliveAndGetCb(mMockConnectManager);
        socketKeepaliveCb.onError(ERROR_INVALID_IP_ADDRESS);

        verify(mMockSocketKeepalive).stop();

        ArgumentCaptor<IkeAlarmConfig> alarmConfigCaptor =
                ArgumentCaptor.forClass(IkeAlarmConfig.class);
        verify(mMockDeps)
                .createSoftwareKeepaliveImpl(any(), any(), any(), alarmConfigCaptor.capture());
        assertEquals(
                TimeUnit.SECONDS.toMillis((long) KEEPALIVE_DELAY_CALLER_CONFIGURED_SECONDS),
                alarmConfigCaptor.getValue().delayMs);

        mIkeNattKeepalive.stop();
        verify(mMockSocketKeepalive).stop();
        verify(mMockSoftwareKeepalive).stop();
    }
}
