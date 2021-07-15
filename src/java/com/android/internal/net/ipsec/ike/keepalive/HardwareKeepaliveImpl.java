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

import static android.net.SocketKeepalive.ERROR_HARDWARE_ERROR;
import static android.net.SocketKeepalive.ERROR_INSUFFICIENT_RESOURCES;
import static android.net.SocketKeepalive.ERROR_INVALID_INTERVAL;
import static android.net.SocketKeepalive.ERROR_INVALID_IP_ADDRESS;
import static android.net.SocketKeepalive.ERROR_INVALID_LENGTH;
import static android.net.SocketKeepalive.ERROR_INVALID_NETWORK;
import static android.net.SocketKeepalive.ERROR_INVALID_PORT;
import static android.net.SocketKeepalive.ERROR_INVALID_SOCKET;
import static android.net.SocketKeepalive.ERROR_SOCKET_NOT_IDLE;
import static android.net.SocketKeepalive.ERROR_UNSUPPORTED;
import static android.net.ipsec.ike.IkeManager.getIkeLog;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.net.SocketKeepalive;

import java.io.IOException;
import java.net.Inet4Address;
import java.util.concurrent.Executors;

/** This class provides methods to manage hardware offload NAT-T keepalive. */
public class HardwareKeepaliveImpl implements IkeNattKeepalive.NattKeepalive {
    private static final String TAG = "HardwareKeepaliveImpl";

    private final int mKeepaliveDelaySeconds;
    private final SocketKeepalive mSocketKeepalive;
    private final HardwareKeepaliveCallback mHardwareKeepaliveCb;

    /** Construct an instance of HardwareKeepaliveImpl */
    public HardwareKeepaliveImpl(
            Context context,
            ConnectivityManager connectMgr,
            int keepaliveDelaySeconds,
            Inet4Address src,
            Inet4Address dest,
            UdpEncapsulationSocket socket,
            Network network,
            HardwareKeepaliveCallback hardwareKeepaliveCb)
            throws IOException {
        // Setup for hardware offload keepalive. Fail to create mSocketKeepalive will cause
        // MySocketKeepaliveCb#onError to be fired
        mKeepaliveDelaySeconds = keepaliveDelaySeconds;
        mHardwareKeepaliveCb = hardwareKeepaliveCb;

        mSocketKeepalive =
                connectMgr.createSocketKeepalive(
                        network,
                        socket,
                        src,
                        dest,
                        Executors.newSingleThreadExecutor(),
                        new MySocketKeepaliveCb());
    }

    @Override
    public void start() {
        mSocketKeepalive.start(mKeepaliveDelaySeconds);
    }

    @Override
    public void stop() {
        mSocketKeepalive.stop();
    }

    @Override
    public void onAlarmFired() {
        // Do thing. Should never be called
    }

    /** Callback interface to receive states change of hardware keepalive */
    public interface HardwareKeepaliveCallback {
        /** Called when there is a hardware error for keepalive. */
        void onHardwareOffloadError();

        /**
         * Called when there is a network or configuration error which cause sending keepalive
         * packet to fail
         */
        void onNetworkError();
    }

    private class MySocketKeepaliveCb extends SocketKeepalive.Callback {
        @Override
        public void onError(int error) {
            getIkeLog().d(TAG, "Hardware offload failed on error: " + error);
            switch (error) {
                case ERROR_INVALID_NETWORK: // fallthrough
                case ERROR_INVALID_IP_ADDRESS: // fallthrough
                case ERROR_INVALID_PORT: // fallthrough
                case ERROR_INVALID_LENGTH: // fallthrough
                case ERROR_INVALID_INTERVAL: // fallthrough
                case ERROR_INVALID_SOCKET: // fallthrough
                case ERROR_SOCKET_NOT_IDLE: // fallthrough
                    mHardwareKeepaliveCb.onNetworkError();
                    return;
                case ERROR_UNSUPPORTED: // fallthrough
                case ERROR_HARDWARE_ERROR: // fallthrough
                case ERROR_INSUFFICIENT_RESOURCES:
                    mHardwareKeepaliveCb.onHardwareOffloadError();
                    return;
                default:
                    mHardwareKeepaliveCb.onNetworkError();
            }
        }
    }
}
