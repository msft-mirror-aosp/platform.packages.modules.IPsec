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

import static android.net.ipsec.ike.IkeManager.getIkeLog;
import static android.system.OsConstants.F_SETFL;
import static android.system.OsConstants.SOCK_DGRAM;
import static android.system.OsConstants.SOCK_NONBLOCK;

import android.net.IpSecManager.UdpEncapsulationSocket;
import android.os.Handler;
import android.system.ErrnoException;
import android.system.Os;
import android.util.LongSparseArray;

import com.android.internal.annotations.VisibleForTesting;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * IkeUdpEncapSocket uses an {@link UdpEncapsulationSocket} to send and receive IKE packets.
 *
 * <p>One UdpEncapsulationSocket instance can only be bound to one IkeUdpEncapSocket instance.
 * IkeUdpEncapSocket maintains a static map to cache all bound UdpEncapsulationSockets and their
 * IkeUdpEncapSocket instances. It returns the existing IkeUdpEncapSocket when it has been bound
 * with user provided {@link UdpEncapsulationSocket}.
 */
public final class IkeUdpEncapSocket extends IkeSocket {
    private static final String TAG = "IkeUdpEncapSocket";

    // A Non-ESP marker helps the recipient to distinguish IKE packets from ESP packets.
    @VisibleForTesting static final int NON_ESP_MARKER_LEN = 4;
    @VisibleForTesting static final byte[] NON_ESP_MARKER = new byte[NON_ESP_MARKER_LEN];

    // Map from UdpEncapsulationSocket to IkeUdpEncapSocket instances.
    private static Map<UdpEncapsulationSocket, IkeUdpEncapSocket> sFdToIkeUdpEncapSocketMap =
            new HashMap<>();

    private static IPacketReceiver sPacketReceiver = new PacketReceiver();

    // UdpEncapsulationSocket for sending and receving IKE packet.
    private final UdpEncapsulationSocket mUdpEncapSocket;

    private IkeUdpEncapSocket(UdpEncapsulationSocket udpEncapSocket, Handler handler) {
        super(handler);
        mUdpEncapSocket = udpEncapSocket;
    }

    /**
     * Get an IkeUdpEncapSocket instance.
     *
     * <p>Return the existing IkeUdpEncapSocket instance if it has been created for the input
     * udpEncapSocket. Otherwise, create and return a new IkeUdpEncapSocket instance.
     *
     * @param udpEncapSocket user provided UdpEncapsulationSocket
     * @param ikeSession the IkeSessionStateMachine that is requesting an IkeUdpEncapSocket.
     * @return an IkeUdpEncapSocket instance
     */
    public static IkeUdpEncapSocket getIkeUdpEncapSocket(
            UdpEncapsulationSocket udpEncapSocket, IkeSessionStateMachine ikeSession)
            throws ErrnoException {
        FileDescriptor fd = udpEncapSocket.getFileDescriptor();

        // {@link PacketReader} requires non-blocking I/O access. Set SOCK_NONBLOCK here.
        Os.fcntlInt(fd, F_SETFL, SOCK_DGRAM | SOCK_NONBLOCK);

        IkeUdpEncapSocket ikeSocket = sFdToIkeUdpEncapSocketMap.get(udpEncapSocket);
        if (ikeSocket == null) {
            ikeSocket = new IkeUdpEncapSocket(udpEncapSocket, new Handler());
            // Create and register FileDescriptor for receiving IKE packet on current thread.
            ikeSocket.start();

            sFdToIkeUdpEncapSocketMap.put(udpEncapSocket, ikeSocket);
        }

        ikeSocket.mAliveIkeSessions.add(ikeSession);
        return ikeSocket;
    }

    /**
     * Get FileDescriptor of mUdpEncapSocket.
     *
     * <p>PacketReader registers a listener for this file descriptor on the thread where
     * IkeUdpEncapSocket is constructed. When there is a read event, this listener is invoked and
     * then calls {@link handlePacket} to handle the received packet.
     */
    @Override
    protected FileDescriptor createFd() {
        return mUdpEncapSocket.getFileDescriptor();
    }

    /**
     * IPacketReceiver provides a package private interface for handling received packet.
     *
     * <p>IPacketReceiver exists so that the interface is injectable for testing.
     */
    interface IPacketReceiver {
        void handlePacket(byte[] recvbuf, LongSparseArray<IkeSessionStateMachine> spiToIkeSession);
    }

    /** Package private */
    @VisibleForTesting
    static final class PacketReceiver implements IPacketReceiver {
        public void handlePacket(
                byte[] recvbuf, LongSparseArray<IkeSessionStateMachine> spiToIkeSession) {
            ByteBuffer byteBuffer = ByteBuffer.wrap(recvbuf);

            // Check the existence of the Non-ESP Marker. A received packet can be either an IKE
            // packet starts with 4 zero-valued bytes Non-ESP Marker or an ESP packet starts with 4
            // bytes ESP SPI. ESP SPI value can never be zero.
            byte[] espMarker = new byte[NON_ESP_MARKER_LEN];
            byteBuffer.get(espMarker);
            if (!Arrays.equals(NON_ESP_MARKER, espMarker)) {
                // Drop the received ESP packet.
                getIkeLog().e(TAG, "Receive an ESP packet.");
                return;
            }

            // Re-direct IKE packet to IkeSessionStateMachine according to the locally generated
            // IKE SPI.
            byte[] ikePacketBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(ikePacketBytes);
            parseAndDemuxIkePacket(ikePacketBytes, spiToIkeSession, TAG);
        }
    }

    /** Package private */
    @VisibleForTesting
    static void setPacketReceiver(IPacketReceiver receiver) {
        sPacketReceiver = receiver;
    }

    /**
     * Handle received IKE packet. Invoked when there is a read event. Any desired copies of
     * |recvbuf| should be made in here, as the underlying byte array is reused across all reads.
     */
    @Override
    protected void handlePacket(byte[] recvbuf, int length) {
        sPacketReceiver.handlePacket(Arrays.copyOfRange(recvbuf, 0, length), mSpiToIkeSession);
    }

    /**
     * Send encoded IKE packet to destination address
     *
     * @param ikePacket encoded IKE packet
     * @param serverAddress IP address of remote server
     */
    @Override
    public void sendIkePacket(byte[] ikePacket, InetAddress serverAddress) {
        getIkeLog()
                .d(
                        TAG,
                        "Send packet to "
                                + serverAddress.getHostAddress()
                                + "( "
                                + ikePacket.length
                                + " bytes)");
        try {
            ByteBuffer buffer = ByteBuffer.allocate(NON_ESP_MARKER_LEN + ikePacket.length);

            // Build outbound UDP Encapsulation packet body for sending IKE message.
            buffer.put(NON_ESP_MARKER).put(ikePacket);
            buffer.rewind();

            // Use unconnected UDP socket because one {@UdpEncapsulationSocket} may be shared by
            // multiple IKE sessions that send messages to different destinations.
            Os.sendto(
                    mUdpEncapSocket.getFileDescriptor(),
                    buffer,
                    0,
                    serverAddress,
                    SERVER_PORT_UDP_ENCAPSULATED);
        } catch (ErrnoException | IOException e) {
            // TODO: Handle exception
        }
    }

    @Override
    public int getIkeServerPort() {
        return SERVER_PORT_UDP_ENCAPSULATED;
    }

    /** Implement {@link AutoCloseable#close()} */
    @Override
    public void close() {
        sFdToIkeUdpEncapSocketMap.remove(mUdpEncapSocket);
        // PacketReader unregisters file descriptor on thread with which the Handler constructor
        // argument is associated.
        super.close();
    }
}
