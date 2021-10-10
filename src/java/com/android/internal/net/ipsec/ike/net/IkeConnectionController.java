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

package com.android.internal.net.ipsec.ike.net;

import static android.net.ipsec.ike.IkeManager.getIkeLog;

import android.net.LinkProperties;
import android.net.Network;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * IkeConnectionController manages all connectivity events for an IKE Session
 *
 * <p>IkeConnectionController's responsibilities include:
 *
 * <ul>
 *   <li>Manage IkeSocket for sending and receiving IKE packets
 *   <li>Monitor and handle network and addresses changes
 *   <li>Schedule NAT-T keepalive
 * </ul>
 *
 * An IkeConnectionController should be set up when IKE Session is being established and should be
 * torn down when the IKE Session is terminated.
 */
public class IkeConnectionController {
    private static final String TAG = IkeConnectionController.class.getSimpleName();

    // The maximum number of attempts allowed for a single DNS resolution.
    private static final int MAX_DNS_RESOLUTION_ATTEMPTS = 3;

    /**
     * Performs DNS resolution and update addresses lists with the resolution results.
     *
     * <p>TODO: Make this method private and non-static when addresses are managed in
     * IkeConnectionController instead of IkeSessionStateMachine. Done in the followup commit.
     */
    public static InetAddress[] resolveAndGetAvailableRemoteAddresses(
            String hostname,
            Network network,
            List<Inet4Address> remoteAddressesV4,
            List<Inet6Address> remoteAddressesV6)
            throws IOException {
        // TODO(b/149954916): Do DNS resolution asynchronously
        InetAddress[] allRemoteAddresses = null;

        for (int attempts = 0;
                attempts < MAX_DNS_RESOLUTION_ATTEMPTS
                        && (allRemoteAddresses == null || allRemoteAddresses.length == 0);
                attempts++) {
            try {
                allRemoteAddresses = network.getAllByName(hostname);
            } catch (UnknownHostException e) {
                final boolean willRetry = attempts + 1 < MAX_DNS_RESOLUTION_ATTEMPTS;
                getIkeLog()
                        .d(
                                TAG,
                                "Failed to look up host for attempt "
                                        + (attempts + 1)
                                        + ": "
                                        + hostname
                                        + " retrying? "
                                        + willRetry,
                                e);
            }
        }
        if (allRemoteAddresses == null || allRemoteAddresses.length == 0) {
            throw new IOException(
                    "DNS resolution for "
                            + hostname
                            + " failed after "
                            + MAX_DNS_RESOLUTION_ATTEMPTS
                            + " attempts");
        }

        getIkeLog()
                .d(
                        TAG,
                        "Resolved addresses for peer: "
                                + Arrays.toString(allRemoteAddresses)
                                + " to replace old addresses: v4="
                                + remoteAddressesV4
                                + " v6="
                                + remoteAddressesV6);
        return allRemoteAddresses;
    }

    /**
     * Returns the remote address for the peer.
     *
     * <p>Prefers IPv6 addresses if:
     *
     * <ul>
     *   <li>an IPv6 address is known for the peer, and
     *   <li>the current underlying Network has a global (non-link local) IPv6 address available
     * </ul>
     *
     * Otherwise, an IPv4 address will be used.
     *
     * <p>TODO: Make this method private and non-static when addresses are managed in
     * IkeConnectionController instead of IkeSessionStateMachine. Done in the followup commit.
     */
    public static InetAddress getRemoteAddress(
            LinkProperties linkProperties,
            List<Inet4Address> remoteAddressesV4,
            List<Inet6Address> remoteAddressesV6) {
        if (!remoteAddressesV6.isEmpty() && linkProperties.hasGlobalIpv6Address()) {
            // TODO(b/175348096): randomly choose from available addresses
            return remoteAddressesV6.get(0);
        } else {
            if (remoteAddressesV4.isEmpty()) {
                throw new IllegalArgumentException("No valid IPv4 or IPv6 addresses for peer");
            }

            // TODO(b/175348096): randomly choose from available addresses
            return remoteAddressesV4.get(0);
        }
    }
}
