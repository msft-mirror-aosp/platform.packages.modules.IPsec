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

package com.android.internal.net.ipsec.test.ike;

import android.os.Handler;
import android.os.test.TestLooper;
import android.system.ErrnoException;

import com.android.internal.net.TestUtils;

import org.junit.Test;

import java.io.IOException;

public final class IkeUdp6WithEncapPortSocketTest extends IkeSocketTestBase {
    private final TestLooper mLooper = new TestLooper();
    private final Handler mHandler = new Handler(mLooper.getLooper());

    private final IkeSocketFactory mIkeSocketFactory =
            new IkeSocketFactory() {
                @Override
                public IkeSocket getIkeSocket(
                        IkeSocketConfig ikeSockConfig, IkeSocket.Callback callback)
                        throws ErrnoException, IOException {
                    return IkeUdp6WithEncapPortSocket.getIkeUdpEncapSocket(
                            ikeSockConfig, callback, mHandler);
                }
            };

    private IkeSocket.IPacketReceiver getPacketReceiver() {
        return new IkeUdpEncapPortPacketHandler.PacketReceiver();
    }

    @Override
    protected void setPacketReceiver(IkeSocket.IPacketReceiver packetReceiver) {
        IkeUdp6WithEncapPortSocket.setPacketReceiver(packetReceiver);
    }

    @Test
    public void testGetAndCloseIkeUdp6WithEncapPortSocketTestSameNetwork() throws Exception {
        verifyGetAndCloseIkeSocketSameConfig(
                mIkeSocketFactory, IkeSocket.SERVER_PORT_UDP_ENCAPSULATED);
    }

    @Test
    public void testGetAndCloseIkeUdp6WithEncapPortSocketTestDifferentNetwork() throws Exception {
        verifyGetAndCloseIkeSocketDifferentConfig(
                mIkeSocketFactory, IkeSocket.SERVER_PORT_UDP_ENCAPSULATED);
    }

    @Test
    public void testReceiveIkePacket() throws Exception {
        verifyIkeUdpSocketReceivePacket(
                mIkeSocketFactory,
                getPacketReceiver(),
                NON_ESP_MARKER_HEX_STRING + IKE_REQ_MESSAGE_HEX_STRING);
    }

    @Test
    public void testHandlePacket() throws Exception {
        verifyHandlePacket(
                TestUtils.hexStringToByteArray(
                        NON_ESP_MARKER_HEX_STRING + IKE_REQ_MESSAGE_HEX_STRING),
                getPacketReceiver());
    }
}
