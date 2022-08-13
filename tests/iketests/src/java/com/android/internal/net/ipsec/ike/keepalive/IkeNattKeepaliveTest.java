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

import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_TEST;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static android.net.SocketKeepalive.ERROR_HARDWARE_ERROR;
import static android.net.SocketKeepalive.ERROR_INVALID_IP_ADDRESS;
import static android.net.ipsec.test.ike.IkeSessionParams.IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES;

import static com.android.internal.net.ipsec.test.ike.keepalive.IkeNattKeepalive.AUTO_KEEPALIVE_DELAY_SEC_CELL;
import static com.android.internal.net.ipsec.test.ike.keepalive.IkeNattKeepalive.AUTO_KEEPALIVE_DELAY_SEC_WIFI;
import static com.android.internal.net.ipsec.test.ike.keepalive.IkeNattKeepalive.KeepaliveConfig;
import static com.android.internal.net.ipsec.test.ike.utils.IkeAlarm.IkeAlarmConfig;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import android.os.Message;

import com.android.internal.net.ipsec.test.ike.utils.IkeAlarm.IkeAlarmConfig;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.net.Inet4Address;
import java.util.concurrent.TimeUnit;

public class IkeNattKeepaliveTest {
    private static final int KEEPALIVE_DELAY = 20;
    private static final int AUTO_KEEPALIVE_DELAY = 50;

    private ConnectivityManager mMockConnectManager;
    private IkeNattKeepalive.Dependencies mMockDeps;
    private SocketKeepalive mMockSocketKeepalive;
    private SoftwareKeepaliveImpl mMockSoftwareKeepalive;

    private IkeNattKeepalive mIkeNattKeepalive;

    @Before
    public void setUp() throws Exception {
        mMockConnectManager = mock(ConnectivityManager.class);
        mMockSocketKeepalive = mock(SocketKeepalive.class);
        resetMockConnectManager();

        mMockDeps = mock(IkeNattKeepalive.Dependencies.class);
        mMockSoftwareKeepalive = mock(SoftwareKeepaliveImpl.class);
        resetMockDeps();

        IkeSessionParams mockIkeParams = mock(IkeSessionParams.class);
        doReturn(KEEPALIVE_DELAY).when(mockIkeParams).getNattKeepAliveDelaySeconds();

        mIkeNattKeepalive = createIkeNattKeepalive(mockIkeParams, mock(NetworkCapabilities.class));
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
        doReturn(AUTO_KEEPALIVE_DELAY).when(mMockDeps).getAutoKeepaliveDelaySec(any(), anyInt());
    }

    private IkeNattKeepalive createIkeNattKeepalive(
            IkeSessionParams mockIkeParams, NetworkCapabilities mockNc) throws Exception {
        final Context mMockContext = mock(Context.class);
        return new IkeNattKeepalive(
                mock(Context.class),
                mMockConnectManager,
                new KeepaliveConfig(
                        mock(Inet4Address.class),
                        mock(Inet4Address.class),
                        mock(UdpEncapsulationSocket.class),
                        mock(Network.class),
                        new IkeAlarmConfig(
                                mMockContext,
                                "TEST",
                                KEEPALIVE_DELAY,
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

    @Test
    public void testStartStopHardwareKeepalive() throws Exception {
        mIkeNattKeepalive.start();
        verify(mMockSocketKeepalive).start(KEEPALIVE_DELAY);

        mIkeNattKeepalive.stop();
        verify(mMockSocketKeepalive).stop();
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
        verify(mMockDeps)
                .createSoftwareKeepaliveImpl(anyObject(), anyObject(), anyObject(), anyObject());

        mIkeNattKeepalive.stop();
        verify(mMockSocketKeepalive).stop();
        verify(mMockSoftwareKeepalive).stop();
    }

    private static int getAutoDelaySeconds(int transportType) throws Exception {
        switch (transportType) {
            case TRANSPORT_WIFI:
                return AUTO_KEEPALIVE_DELAY_SEC_WIFI;
            case TRANSPORT_CELLULAR:
                return AUTO_KEEPALIVE_DELAY_SEC_CELL;
            default:
                throw new IllegalArgumentException(
                        "Auto keepalives not enabled for transportType " + transportType);
        }
    }

    private void verifyAutoKeepalive(int transportType, int expectedDelaySec) throws Exception {
        final IkeSessionParams mockIkeParams = mock(IkeSessionParams.class);
        doReturn(true).when(mockIkeParams).hasIkeOption(IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES);
        doReturn(KEEPALIVE_DELAY).when(mockIkeParams).getNattKeepAliveDelaySeconds();

        final NetworkCapabilities mockNc = mock(NetworkCapabilities.class);
        doReturn(true).when(mockNc).hasTransport(transportType);

        // Forget the call in setup()
        reset(mMockSocketKeepalive);
        resetMockConnectManager();
        resetMockDeps();

        IkeNattKeepalive nattKeepAlive = createIkeNattKeepalive(mockIkeParams, mockNc);

        if (transportType == TRANSPORT_WIFI || transportType == TRANSPORT_CELLULAR) {
            verify(mMockDeps)
                    .getAutoKeepaliveDelaySec(mockIkeParams, getAutoDelaySeconds(transportType));
        } else {
            verify(mMockDeps, never()).getAutoKeepaliveDelaySec(any(), anyInt());
        }

        // Verify hardware keepalive
        nattKeepAlive.start();
        verify(mMockSocketKeepalive).start(expectedDelaySec);

        // Verify software keepalive
        SocketKeepalive.Callback socketKeepaliveCb =
                verifyHardwareKeepaliveAndGetCb(mMockConnectManager);
        socketKeepaliveCb.onError(ERROR_HARDWARE_ERROR);

        ArgumentCaptor<IkeAlarmConfig> alarmConfigCaptor =
                ArgumentCaptor.forClass(IkeAlarmConfig.class);

        verify(mMockDeps)
                .createSoftwareKeepaliveImpl(any(), any(), any(), alarmConfigCaptor.capture());
        assertEquals(
                TimeUnit.SECONDS.toMillis((long) expectedDelaySec),
                alarmConfigCaptor.getValue().delayMs);

        mIkeNattKeepalive.stop();
    }

    @Test
    public void testAutoKeepaliveOnWifi() throws Exception {
        verifyAutoKeepalive(TRANSPORT_WIFI, AUTO_KEEPALIVE_DELAY);
    }

    @Test
    public void testAutoKeepaliveOnCell() throws Exception {
        verifyAutoKeepalive(TRANSPORT_CELLULAR, AUTO_KEEPALIVE_DELAY);
    }

    @Test
    public void testAutoKeepaliveOnNonWifiOrCell() throws Exception {
        verifyAutoKeepalive(TRANSPORT_TEST, KEEPALIVE_DELAY);
    }

    private void verifyGetAutoKeepaliveDelaySec(
            int callerConfiguredDelay, int autoKeepaliveDelay, int expectedDelay) throws Exception {
        final IkeSessionParams mockIkeParams = mock(IkeSessionParams.class);
        doReturn(callerConfiguredDelay).when(mockIkeParams).getNattKeepAliveDelaySeconds();

        final int actualDelay =
                new IkeNattKeepalive.Dependencies()
                        .getAutoKeepaliveDelaySec(mockIkeParams, autoKeepaliveDelay);
        assertEquals(expectedDelay, actualDelay);
    }

    @Test
    public void testGetAutoKeepaliveDelaySecCallerOverride() throws Exception {
        verifyGetAutoKeepaliveDelaySec(
                10 /* callerConfiguredDelay */,
                20 /* autoKeepaliveDelay */,
                10 /* expectedDelay */);
    }

    @Test
    public void testGetAutoKeepaliveDelaySecNoCallerOverride() throws Exception {
        verifyGetAutoKeepaliveDelaySec(
                30 /* callerConfiguredDelay */,
                20 /* autoKeepaliveDelay */,
                20 /* expectedDelay */);
    }
}
