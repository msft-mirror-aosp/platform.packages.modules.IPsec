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

package com.android.internal.net.ipsec.test.ike;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyObject;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.test.TestLooper;
import android.system.ErrnoException;
import android.util.Log;

import androidx.test.InstrumentationRegistry;

import com.android.internal.net.TestUtils;
import com.android.internal.net.ipsec.test.ike.testutils.MockIpSecTestUtils;
import com.android.server.IpSecService;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public final class IkeUdpEncapSocketTest extends IkeSocketTestBase {
    private final TestLooper mLooper = new TestLooper();

    private UdpEncapsulationSocket mSpyUdpEncapSocket;

    private UdpEncapsulationSocket mSpyDummyUdpEncapSocketOne;
    private UdpEncapsulationSocket mSpyDummyUdpEncapSocketTwo;
    private IpSecManager mSpyIpSecManager;

    private final IkeSocketFactory mIkeSocketFactory =
            new IkeSocketFactory() {
                @Override
                public IkeSocket getIkeSocket(Network network, IkeSessionStateMachine ikeSession)
                        throws ErrnoException, IOException {
                    try {
                        return IkeUdpEncapSocket.getIkeUdpEncapSocket(
                                network, mSpyIpSecManager, ikeSession, mLooper.getLooper());
                    } catch (ResourceUnavailableException e) {
                        throw new IllegalStateException(e);
                    }
                }
            };

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        Context context = InstrumentationRegistry.getContext();
        IpSecManager ipSecManager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
        mSpyUdpEncapSocket = spy(ipSecManager.openUdpEncapsulationSocket());

        MockIpSecTestUtils mockIpSecTestUtils = MockIpSecTestUtils.setUpMockIpSec();
        IpSecManager dummyIpSecManager = mockIpSecTestUtils.getIpSecManager();
        IpSecService ipSecService = mockIpSecTestUtils.getIpSecService();

        when(ipSecService.openUdpEncapsulationSocket(anyInt(), anyObject()))
                .thenReturn(MockIpSecTestUtils.buildDummyIpSecUdpEncapResponse(12345));
        mSpyDummyUdpEncapSocketOne = spy(dummyIpSecManager.openUdpEncapsulationSocket());

        when(ipSecService.openUdpEncapsulationSocket(anyInt(), anyObject()))
                .thenReturn(MockIpSecTestUtils.buildDummyIpSecUdpEncapResponse(23456));
        mSpyDummyUdpEncapSocketTwo = spy(dummyIpSecManager.openUdpEncapsulationSocket());

        mSpyIpSecManager = spy(dummyIpSecManager);
        doReturn(mSpyDummyUdpEncapSocketOne)
                .doReturn(mSpyDummyUdpEncapSocketTwo)
                .when(mSpyIpSecManager)
                .openUdpEncapsulationSocket();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        mSpyUdpEncapSocket.close();

        super.tearDown();
    }

    @Override
    protected IkeSocket.IPacketReceiver getPacketReceiver() {
        return new IkeUdpEncapSocket.PacketReceiver();
    }

    @Test
    public void testGetAndCloseIkeUdpEncapSocketSameNetwork() throws Exception {
        verifyGetAndCloseIkeSocketSameNetwork(
                mIkeSocketFactory, IkeSocket.SERVER_PORT_UDP_ENCAPSULATED);
        verify(mSpyIpSecManager).openUdpEncapsulationSocket();
        verify(mSpyDummyUdpEncapSocketOne).close();
    }

    @Test
    public void testGetAndCloseIkeUdpEncapSocketDifferentNetwork() throws Exception {
        verifyGetAndCloseIkeSocketDifferentNetwork(
                mIkeSocketFactory, IkeSocket.SERVER_PORT_UDP_ENCAPSULATED);
        verify(mSpyIpSecManager, times(2)).openUdpEncapsulationSocket();
        verify(mSpyDummyUdpEncapSocketOne).close();
        verify(mSpyDummyUdpEncapSocketTwo).close();
    }

    @Ignore
    public void disableTestSendIkePacket() throws Exception {
        // Must be prepared here; AndroidJUnitRunner runs tests on different threads
        // from the setUp() call. Since the new Handler() call is run in
        // getIkeUdpEncapSocket, the Looper must be prepared here.
        if (Looper.myLooper() == null) Looper.prepare();

        // Send IKE packet
        IkeUdpEncapSocket ikeSocket =
                IkeUdpEncapSocket.getIkeUdpEncapSocket(
                        mMockNetwork,
                        mSpyIpSecManager,
                        mMockIkeSessionStateMachine,
                        Looper.myLooper());
        ikeSocket.sendIkePacket(mDataOne, IPV4_LOOPBACK);

        byte[] receivedData = receive(mDummyRemoteServerFd);

        // Verify received data
        ByteBuffer expectedBuffer =
                ByteBuffer.allocate(IkeUdpEncapSocket.NON_ESP_MARKER_LEN + mDataOne.length);
        expectedBuffer.put(IkeUdpEncapSocket.NON_ESP_MARKER).put(mDataOne);

        assertArrayEquals(expectedBuffer.array(), receivedData);

        ikeSocket.releaseReference(mMockIkeSessionStateMachine);
    }

    @Test
    public void testReceiveIkePacket() throws Exception {
        doReturn(mSpyUdpEncapSocket).when(mSpyIpSecManager).openUdpEncapsulationSocket();

        // Create working thread.
        HandlerThread mIkeThread = new HandlerThread("IkeUdpEncapSocketTest");
        mIkeThread.start();

        // Create IkeUdpEncapSocket on working thread.
        IkeUdpEncapSocketReceiver socketReceiver = new IkeUdpEncapSocketReceiver();
        TestCountDownLatch createLatch = new TestCountDownLatch();
        mIkeThread
                .getThreadHandler()
                .post(
                        () -> {
                            try {
                                socketReceiver.setIkeUdpEncapSocket(
                                        IkeUdpEncapSocket.getIkeUdpEncapSocket(
                                                mMockNetwork,
                                                mSpyIpSecManager,
                                                mMockIkeSessionStateMachine,
                                                mIkeThread.getLooper()));
                                createLatch.countDown();
                                Log.d("IkeUdpEncapSocketTest", "IkeUdpEncapSocket created.");
                            } catch (ErrnoException
                                    | IOException
                                    | ResourceUnavailableException e) {
                                Log.e(
                                        "IkeUdpEncapSocketTest",
                                        "error encountered creating IkeUdpEncapSocket ",
                                        e);
                            }
                        });
        createLatch.await();

        IkeUdpEncapSocket ikeSocket = socketReceiver.getIkeUdpEncapSocket();
        assertNotNull(ikeSocket);

        // Configure IkeUdpEncapSocket
        TestCountDownLatch receiveLatch = new TestCountDownLatch();
        DummyPacketReceiver packetReceiver = new DummyPacketReceiver(receiveLatch);
        IkeUdpEncapSocket.setPacketReceiver(packetReceiver);
        try {
            // Send first packet.
            sendToIkeUdpEncapSocket(mDummyRemoteServerFd, mDataOne, IPV4_LOOPBACK);
            receiveLatch.await();

            assertArrayEquals(mDataOne, packetReceiver.mReceivedData);

            // Send second packet.
            sendToIkeUdpEncapSocket(mDummyRemoteServerFd, mDataTwo, IPV4_LOOPBACK);
            receiveLatch.await();

            assertArrayEquals(mDataTwo, packetReceiver.mReceivedData);

            // Close IkeUdpEncapSocket.
            TestCountDownLatch closeLatch = new TestCountDownLatch();
            mIkeThread
                    .getThreadHandler()
                    .post(
                            () -> {
                                ikeSocket.releaseReference(mMockIkeSessionStateMachine);
                                closeLatch.countDown();
                            });
            closeLatch.await();

            verify(mSpyUdpEncapSocket).close();
            verifyCloseFd(mSpyUdpEncapSocket.getFileDescriptor());

            mIkeThread.quitSafely();
        } finally {
            IkeUdpEncapSocket.setPacketReceiver(getPacketReceiver());
        }
    }

    @Test
    public void testHandlePacket() throws Exception {
        byte[] recvBuf =
                TestUtils.hexStringToByteArray(
                        NON_ESP_MARKER_HEX_STRING + IKE_REQ_MESSAGE_HEX_STRING);

        verifyHandlePacket(recvBuf, getPacketReceiver());
    }

    @Test
    public void testHandleEspPacket() throws Exception {
        byte[] recvBuf =
                TestUtils.hexStringToByteArray(
                        NON_ESP_MARKER_HEX_STRING + IKE_REQ_MESSAGE_HEX_STRING);
        // Modify Non-ESP Marker
        recvBuf[0] = 1;

        getPacketReceiver().handlePacket(recvBuf, mSpiToIkeStateMachineMap);

        verify(mMockIkeSessionStateMachine, never()).receiveIkePacket(any(), any());
    }

    @Test
    public void testHandlePacketWithMalformedHeader() throws Exception {
        String malformedIkePacketHexString = "5f54bf6d8b48e6e100000000000000002120220800000000";
        byte[] recvBuf =
                TestUtils.hexStringToByteArray(
                        NON_ESP_MARKER_HEX_STRING + malformedIkePacketHexString);

        getPacketReceiver().handlePacket(recvBuf, mSpiToIkeStateMachineMap);

        verify(mMockIkeSessionStateMachine, never()).receiveIkePacket(any(), any());
    }

    private void sendToIkeUdpEncapSocket(FileDescriptor fd, byte[] data, InetAddress destAddress)
            throws Exception {
        sendToIkeSocket(fd, data, destAddress, mSpyUdpEncapSocket.getPort());
    }

    private static class IkeUdpEncapSocketReceiver {
        private IkeUdpEncapSocket mIkeUdpEncapSocket;

        void setIkeUdpEncapSocket(IkeUdpEncapSocket ikeSocket) {
            mIkeUdpEncapSocket = ikeSocket;
        }

        IkeUdpEncapSocket getIkeUdpEncapSocket() {
            return mIkeUdpEncapSocket;
        }
    }
}
