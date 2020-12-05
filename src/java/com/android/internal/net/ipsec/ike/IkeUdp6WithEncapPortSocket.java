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

import android.net.Network;
import android.os.Handler;
import android.system.ErrnoException;

import java.io.FileDescriptor;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * IkeUdp6WithEncapPortSocket uses an IPv6-bound {@link FileDescriptor} to send and receive IKE
 * packets.
 *
 * <p>IkeUdp6WithEncapPortSocket is usually used when IKE Session has IPv6 address and is required
 * to send message to port 4500, as per MOBIKE spec (RFC 4555).
 *
 * <p>Caller MUST provide one {@link Network} when trying to get an instance of
 * IkeUdp6WithEncapPortSocket. Each {@link Network} will only be bound to by one
 * IkeUdp6WithEncapPortSocket instance. When caller requests an IkeUdp6WithEncapPortSocket with an
 * already bound {@link Network}, the existing instance will be returned.
 */
public final class IkeUdp6WithEncapPortSocket extends IkeUdp6Socket {
    private static final String TAG = IkeUdp6WithEncapPortSocket.class.getSimpleName();

    // Map from Network to IkeUdp6WithEncapPortSocket instances.
    private static Map<Network, IkeUdp6WithEncapPortSocket> sNetworkToUdp6SocketMap =
            new HashMap<>();

    private IkeUdp6WithEncapPortSocket(FileDescriptor socket, Network network, Handler handler) {
        super(socket, network, handler);
    }

    /**
     * Get an IkeUdp6WithEncapPortSocket instance.
     *
     * <p>Return the existing IkeUdp6WithEncapPortSocket instance if it has been created for the
     * input Network. Otherwise, create and return a new IkeUdp6WithEncapPortSocket instance.
     *
     * @param network the Network this socket will be bound to
     * @param ikeSession the IkeSessionStateMachine that is requesting an
     *     IkeUdp6WithEncapPortSocket.
     * @param handler the Handler used to process received packets
     * @return an IkeUdp6WithEncapPortSocket instance
     */
    public static IkeUdp6WithEncapPortSocket getInstance(
            Network network, IkeSessionStateMachine ikeSession, Handler handler)
            throws ErrnoException, IOException {
        IkeUdp6WithEncapPortSocket ikeSocket = sNetworkToUdp6SocketMap.get(network);
        if (ikeSocket == null) {
            ikeSocket =
                    new IkeUdp6WithEncapPortSocket(openUdp6SockNonBlock(network), network, handler);

            // Create and register FileDescriptor for receiving IKE packet on current thread.
            ikeSocket.start();

            sNetworkToUdp6SocketMap.put(network, ikeSocket);
        }
        ikeSocket.mAliveIkeSessions.add(ikeSession);
        return ikeSocket;
    }

    @Override
    public int getIkeServerPort() {
        return SERVER_PORT_UDP_ENCAPSULATED;
    }

    /** Implement {@link AutoCloseable#close()} */
    @Override
    public void close() {
        sNetworkToUdp6SocketMap.remove(getNetwork());

        super.close();
    }
}
