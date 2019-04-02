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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.content.Context;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.HandlerThread;
import android.os.Looper;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import android.util.LongSparseArray;

import androidx.test.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class IkeSocketTest {
    private static final int REMOTE_RECV_BUFF_SIZE = 2048;
    private static final int TIMEOUT = 1000;

    private static final String DATA_ONE = "one 1";
    private static final String DATA_TWO = "two 2";

    private static final String IPV4_LOOPBACK = "127.0.0.1";

    private byte[] mDataOne;
    private byte[] mDataTwo;

    private UdpEncapsulationSocket mClientUdpEncapSocket;
    private InetAddress mLocalAddress;
    private FileDescriptor mDummyRemoteServerFd;

    @Before
    public void setUp() throws Exception {
        Context context = InstrumentationRegistry.getContext();
        IpSecManager ipSecManager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
        mClientUdpEncapSocket = ipSecManager.openUdpEncapsulationSocket();

        mLocalAddress = InetAddress.getByName(IPV4_LOOPBACK);
        mDummyRemoteServerFd = getBoundUdpSocket(mLocalAddress);

        mDataOne = DATA_ONE.getBytes("UTF-8");
        mDataTwo = DATA_TWO.getBytes("UTF-8");
    }

    @After
    public void tearDown() throws Exception {
        mClientUdpEncapSocket.close();
        IkeSocket.setPacketReceiver(new IkeSocket.PacketReceiver());
        Os.close(mDummyRemoteServerFd);
    }

    private static FileDescriptor getBoundUdpSocket(InetAddress address) throws Exception {
        FileDescriptor sock =
                Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);
        Os.bind(sock, address, IkeSocket.IKE_SERVER_PORT);
        return sock;
    }

    @Test
    public void testGetAndCloseIkeSocket() throws Exception {
        if (Looper.myLooper() == null) Looper.myLooper().prepare();

        IkeSocket ikeSocketOne = IkeSocket.getIkeSocket(mClientUdpEncapSocket);
        assertEquals(1, ikeSocketOne.mRefCount);

        IkeSocket ikeSocketTwo = IkeSocket.getIkeSocket(mClientUdpEncapSocket);
        assertEquals(ikeSocketOne, ikeSocketTwo);
        assertEquals(2, ikeSocketTwo.mRefCount);

        ikeSocketOne.releaseReference();
        assertEquals(1, ikeSocketOne.mRefCount);

        ikeSocketTwo.releaseReference();
        assertEquals(0, ikeSocketTwo.mRefCount);
    }

    @Test
    public void testSendIkePacket() throws Exception {
        if (Looper.myLooper() == null) Looper.myLooper().prepare();

        // Send IKE packet
        IkeSocket ikeSocket = IkeSocket.getIkeSocket(mClientUdpEncapSocket);
        ikeSocket.sendIkePacket(mDataOne, mLocalAddress);

        byte[] receivedData = receive(mDummyRemoteServerFd);

        // Verify received data
        ByteBuffer expectedBuffer =
                ByteBuffer.allocate(IkeSocket.NON_ESP_MARKER_LEN + mDataOne.length);
        expectedBuffer.put(new byte[IkeSocket.NON_ESP_MARKER_LEN]).put(mDataOne);

        assertArrayEquals(expectedBuffer.array(), receivedData);

        ikeSocket.releaseReference();
    }

    @Test
    public void testReceiveIkePacket() throws Exception {
        // Create working thread.
        HandlerThread mIkeThread = new HandlerThread("IkeSocketTest");
        mIkeThread.start();

        // Create IkeSocket on working thread.
        IkeSocketReceiver socketReceiver = new IkeSocketReceiver();
        TestCountDownLatch createLatch = new TestCountDownLatch();
        mIkeThread
                .getThreadHandler()
                .post(
                        () -> {
                            try {
                                socketReceiver.setIkeSocket(
                                        IkeSocket.getIkeSocket(mClientUdpEncapSocket));
                                createLatch.countDown();
                                Log.d("IkeSocketTest", "IkeSocket created.");
                            } catch (ErrnoException e) {
                                Log.e("IkeSocketTest", "error encountered creating IkeSocket ", e);
                            }
                        });
        createLatch.await();

        IkeSocket ikeSocket = socketReceiver.getIkeSocket();
        assertNotNull(ikeSocket);

        // Configure IkeSocket
        TestCountDownLatch receiveLatch = new TestCountDownLatch();
        DummyPacketReceiver packetReceiver = new DummyPacketReceiver(receiveLatch);
        IkeSocket.setPacketReceiver(packetReceiver);

        // Send first packet.
        sendToIkeSocket(mDummyRemoteServerFd, mDataOne, mLocalAddress);
        receiveLatch.await();

        assertEquals(1, ikeSocket.numPacketsReceived());
        assertArrayEquals(mDataOne, packetReceiver.mReceivedData);

        // Send second packet.
        sendToIkeSocket(mDummyRemoteServerFd, mDataTwo, mLocalAddress);
        receiveLatch.await();

        assertEquals(2, ikeSocket.numPacketsReceived());
        assertArrayEquals(mDataTwo, packetReceiver.mReceivedData);

        // Close IkeSocket.
        TestCountDownLatch closeLatch = new TestCountDownLatch();
        ikeSocket
                .getHandler()
                .post(
                        () -> {
                            ikeSocket.releaseReference();
                            closeLatch.countDown();
                        });
        closeLatch.await();

        mIkeThread.quitSafely();
    }

    private byte[] receive(FileDescriptor mfd) throws Exception {
        byte[] receiveBuffer = new byte[REMOTE_RECV_BUFF_SIZE];
        AtomicInteger bytesRead = new AtomicInteger(-1);
        Thread receiveThread =
                new Thread(
                        () -> {
                            while (bytesRead.get() < 0) {
                                try {
                                    bytesRead.set(
                                            Os.recvfrom(
                                                    mDummyRemoteServerFd,
                                                    receiveBuffer,
                                                    0,
                                                    REMOTE_RECV_BUFF_SIZE,
                                                    0,
                                                    null));
                                } catch (Exception e) {
                                    Log.e(
                                            "IkeSocketTest",
                                            "Error encountered reading from socket",
                                            e);
                                }
                            }
                            Log.d(
                                    "IkeSocketTest",
                                    "Packet received with size of " + bytesRead.get());
                        });

        receiveThread.start();
        receiveThread.join(TIMEOUT);

        return Arrays.copyOfRange(receiveBuffer, 0, bytesRead.get());
    }

    private void sendToIkeSocket(FileDescriptor fd, byte[] data, InetAddress destAddress)
            throws Exception {
        Os.sendto(fd, data, 0, data.length, 0, destAddress, mClientUdpEncapSocket.getPort());
    }

    private static class IkeSocketReceiver {
        private IkeSocket mIkeSocket;

        void setIkeSocket(IkeSocket ikeSocket) {
            mIkeSocket = ikeSocket;
        }

        IkeSocket getIkeSocket() {
            return mIkeSocket;
        }
    }

    private static class DummyPacketReceiver implements IkeSocket.IPacketReceiver {
        byte[] mReceivedData = null;
        final TestCountDownLatch mLatch;

        DummyPacketReceiver(TestCountDownLatch latch) {
            mLatch = latch;
        }

        public void handlePacket(
                byte[] revbuf, LongSparseArray<IkeSessionStateMachine> spiToIkeSession) {
            mReceivedData = Arrays.copyOfRange(revbuf, 0, revbuf.length);
            mLatch.countDown();
            Log.d("IkeSocketTest", "Packet received");
        }
    }

    private static class TestCountDownLatch {
        private CountDownLatch mLatch;

        TestCountDownLatch() {
            reset();
        }

        private void reset() {
            mLatch = new CountDownLatch(1);
        }

        void countDown() {
            mLatch.countDown();
        }

        void await() {
            try {
                if (!mLatch.await(TIMEOUT, TimeUnit.MILLISECONDS)) {
                    fail("Time out");
                }
            } catch (InterruptedException e) {
                fail(e.toString());
            }
            reset();
        }
    }
}
