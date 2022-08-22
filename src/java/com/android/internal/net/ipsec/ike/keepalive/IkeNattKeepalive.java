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

package com.android.internal.net.ipsec.ike.keepalive;

import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static android.net.ipsec.ike.IkeManager.getIkeLog;
import static android.net.ipsec.ike.IkeSessionParams.IKE_NATT_KEEPALIVE_DELAY_SEC_MAX;
import static android.net.ipsec.ike.IkeSessionParams.IKE_NATT_KEEPALIVE_DELAY_SEC_MIN;
import static android.net.ipsec.ike.IkeSessionParams.IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES;

import static com.android.internal.net.ipsec.ike.IkeContext.CONFIG_AUTO_NATT_KEEPALIVES_CELLULAR_TIMEOUT_OVERRIDE_SECONDS;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ipsec.ike.IkeSessionParams;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.net.ipsec.ike.IkeContext;
import com.android.internal.net.ipsec.ike.utils.IkeAlarm.IkeAlarmConfig;

import java.io.IOException;
import java.net.Inet4Address;
import java.util.concurrent.TimeUnit;

/**
 * This class provides methods to manage NAT-T keepalive for a UdpEncapsulationSocket.
 *
 * <p>Upon calling {@link start()}, this class will start a NAT-T keepalive, using hardware offload
 * if available. If hardware offload is not available, a software keepalive will be attempted.
 */
public class IkeNattKeepalive {
    private static final String TAG = "IkeNattKeepalive";

    @VisibleForTesting public static final int AUTO_KEEPALIVE_DELAY_SEC_WIFI = 15;
    @VisibleForTesting public static final int AUTO_KEEPALIVE_DELAY_SEC_CELL = 150;

    private final Dependencies mDeps;

    private NattKeepalive mNattKeepalive;

    /** Construct an instance of IkeNattKeepalive */
    public IkeNattKeepalive(
            IkeContext ikeContext,
            ConnectivityManager connectMgr,
            KeepaliveConfig nattKeepaliveConfig)
            throws IOException {
        this(ikeContext, connectMgr, nattKeepaliveConfig, new Dependencies());
    }

    IkeNattKeepalive(
            IkeContext ikeContext,
            ConnectivityManager connectMgr,
            KeepaliveConfig nattKeepaliveConfig,
            Dependencies deps)
            throws IOException {
        int keepaliveDelaySeconds =
                getKeepaliveDelaySec(
                        ikeContext, nattKeepaliveConfig.ikeParams, nattKeepaliveConfig.nc);

        mNattKeepalive =
                new HardwareKeepaliveImpl(
                        ikeContext.getContext(),
                        connectMgr,
                        keepaliveDelaySeconds,
                        nattKeepaliveConfig.src,
                        nattKeepaliveConfig.dest,
                        nattKeepaliveConfig.socket,
                        nattKeepaliveConfig.network,
                        new HardwareKeepaliveCb(
                                ikeContext.getContext(),
                                nattKeepaliveConfig.dest,
                                nattKeepaliveConfig.socket,
                                nattKeepaliveConfig.ikeAlarmConfig.buildCopyWithDelayMs(
                                        TimeUnit.SECONDS.toMillis((long) keepaliveDelaySeconds))));
        mDeps = deps;
    }

    @VisibleForTesting
    static int getKeepaliveDelaySec(
            IkeContext ikeContext, IkeSessionParams ikeParams, NetworkCapabilities nc) {
        int keepaliveDelaySeconds = ikeParams.getNattKeepAliveDelaySeconds();

        if (ikeParams.hasIkeOption(IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES)) {
            if (nc.hasTransport(TRANSPORT_WIFI)) {
                // Most of the time, IKE Session will use shorter keepalive timer on WiFi. Thus
                // choose the Wifi timer as a more conservative value when the NeworkCapabilities
                // have both TRANSPORT_WIFI and TRANSPORT_CELLULAR
                final int autoDelaySeconds = AUTO_KEEPALIVE_DELAY_SEC_WIFI;
                keepaliveDelaySeconds = Math.min(keepaliveDelaySeconds, autoDelaySeconds);
            } else if (nc.hasTransport(TRANSPORT_CELLULAR)) {
                final int autoDelaySeconds =
                        ikeContext.getDeviceConfigPropertyInt(
                                CONFIG_AUTO_NATT_KEEPALIVES_CELLULAR_TIMEOUT_OVERRIDE_SECONDS,
                                IKE_NATT_KEEPALIVE_DELAY_SEC_MIN,
                                IKE_NATT_KEEPALIVE_DELAY_SEC_MAX,
                                AUTO_KEEPALIVE_DELAY_SEC_CELL);
                keepaliveDelaySeconds = Math.min(keepaliveDelaySeconds, autoDelaySeconds);
            }
        }

        return keepaliveDelaySeconds;
    }

    /** Configuration object for constructing an IkeNattKeepalive instance */
    public static class KeepaliveConfig {
        public final Inet4Address src;
        public final Inet4Address dest;
        public final UdpEncapsulationSocket socket;
        public final Network network;
        public final IkeAlarmConfig ikeAlarmConfig;
        public final IkeSessionParams ikeParams;
        public final NetworkCapabilities nc;

        public KeepaliveConfig(
                Inet4Address src,
                Inet4Address dest,
                UdpEncapsulationSocket socket,
                Network network,
                IkeAlarmConfig ikeAlarmConfig,
                IkeSessionParams ikeParams,
                NetworkCapabilities nc) {
            this.src = src;
            this.dest = dest;
            this.socket = socket;
            this.network = network;
            this.ikeAlarmConfig = ikeAlarmConfig;
            this.ikeParams = ikeParams;
            this.nc = nc;
        }
    }

    /** Start keepalive */
    public void start() {
        // Try keepalive using hardware offload first
        getIkeLog().d(TAG, "Start NAT-T keepalive");
        mNattKeepalive.start();
    }

    /** Stop keepalive */
    public void stop() {
        getIkeLog().d(TAG, "Stop NAT-T keepalive");

        mNattKeepalive.stop();
    }

    /** Receive a keepalive alarm */
    public void onAlarmFired() {
        mNattKeepalive.onAlarmFired();
    }

    /** Interface that a keepalive implementation MUST provide to support NAT-T keepalive for IKE */
    public interface NattKeepalive {
        /** Start keepalive */
        void start();
        /** Stop keepalive */
        void stop();
        /** Receive a keepalive alarm */
        void onAlarmFired();
    }

    static class Dependencies {
        SoftwareKeepaliveImpl createSoftwareKeepaliveImpl(
                Context context,
                Inet4Address dest,
                UdpEncapsulationSocket socket,
                IkeAlarmConfig alarmConfig) {
            return new SoftwareKeepaliveImpl(context, dest, socket, alarmConfig);
        }
    }

    private class HardwareKeepaliveCb implements HardwareKeepaliveImpl.HardwareKeepaliveCallback {
        private final Context mContext;
        private final Inet4Address mDest;
        private final UdpEncapsulationSocket mSocket;
        private final IkeAlarmConfig mIkeAlarmConfig;

        HardwareKeepaliveCb(
                Context context,
                Inet4Address dest,
                UdpEncapsulationSocket socket,
                IkeAlarmConfig ikeAlarmConfig) {
            mContext = context;
            mDest = dest;
            mSocket = socket;
            mIkeAlarmConfig = ikeAlarmConfig;
        }

        @Override
        public void onHardwareOffloadError() {
            getIkeLog().d(TAG, "Switch to software keepalive");
            mNattKeepalive.stop();

            mNattKeepalive =
                    mDeps.createSoftwareKeepaliveImpl(mContext, mDest, mSocket, mIkeAlarmConfig);
            mNattKeepalive.start();
        }

        @Override
        public void onNetworkError() {
            // Stop doing keepalive when getting network error since it will also fail software
            // keepalive. Considering the only user of IkeNattKeepalive is IkeSessionStateMachine,
            // not notifying user this error won't bring user extra risk. When there is a network
            // error, IkeSessionStateMachine will eventually hit the max request retransmission
            // times and be terminated anyway.

            // TODO: b/182209475 Terminate IKE Sessions when
            // HardwareKeepaliveCallback#onNetworkError is fired
            stop();
        }
    }
}
