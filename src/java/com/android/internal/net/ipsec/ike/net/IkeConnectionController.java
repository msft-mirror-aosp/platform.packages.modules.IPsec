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
import static android.net.ipsec.ike.IkeSessionParams.IKE_OPTION_FORCE_PORT_4500;

import android.annotation.IntDef;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkRequest;
import android.net.ipsec.ike.IkeSessionConnectionInfo;
import android.net.ipsec.ike.IkeSessionParams;
import android.net.ipsec.ike.exceptions.IkeInternalException;
import android.os.Handler;
import android.system.ErrnoException;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.net.ipsec.ike.IkeContext;
import com.android.internal.net.ipsec.ike.IkeSocket;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
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
public class IkeConnectionController implements IkeNetworkUpdater {
    private static final String TAG = IkeConnectionController.class.getSimpleName();

    // The maximum number of attempts allowed for a single DNS resolution.
    private static final int MAX_DNS_RESOLUTION_ATTEMPTS = 3;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({NAT_TRAVERSAL_SUPPORT_NOT_CHECKED, NAT_TRAVERSAL_UNSUPPORTED, NAT_TRAVERSAL_SUPPORTED})
    public @interface NatStatus {}

    /** The IKE client has not checked whether the server supports NAT-T */
    public static final int NAT_TRAVERSAL_SUPPORT_NOT_CHECKED = 0;
    /** The IKE server does not support NAT-T */
    public static final int NAT_TRAVERSAL_UNSUPPORTED = 1;
    /** The IKE server supports NAT-T */
    public static final int NAT_TRAVERSAL_SUPPORTED = 2;

    // TODO: Remove NAT_TRAVERSAL_SUPPORTED ,and add NAT_NOT_DETECTED and NAT_DETECTED when
    // IkeConnectionController can manage IkeNattKeepalive

    private final IkeContext mIkeContext;
    private final ConnectivityManager mConnectivityManager;
    private final IkeLocalAddressGenerator mIkeLocalAddressGenerator;
    private final Callback mCallback;

    private final boolean mForcePort4500;
    private final boolean mUseCallerConfiguredNetwork;
    private final String mRemoteHostname;

    /** Underlying network for this IKE Session. May change if mobility handling is enabled. */
    private Network mNetwork;
    /**
     * Network callback used to keep IkeConnectionController aware of network changes when mobility
     * handling is enabled.
     */
    private IkeNetworkCallbackBase mNetworkCallback;

    /** Local address assigned on device. */
    private InetAddress mLocalAddress;
    /** Remote address resolved from caller configured hostname. */
    private InetAddress mRemoteAddress;
    /** Available remote addresses that are v4. */
    private final List<Inet4Address> mRemoteAddressesV4 = new ArrayList<>();
    /** Available remote addresses that are v6. */
    private final List<Inet6Address> mRemoteAddressesV6 = new ArrayList<>();

    @NatStatus private int mNatStatus;

    /** Constructor for IkeConnectionController */
    public IkeConnectionController(Config config) {
        mIkeContext = config.ikeContext;
        mConnectivityManager = mIkeContext.getContext().getSystemService(ConnectivityManager.class);
        mIkeLocalAddressGenerator = config.localAddressGenerator;
        mCallback = config.callback;

        mForcePort4500 = config.ikeParams.hasIkeOption(IKE_OPTION_FORCE_PORT_4500);
        mRemoteHostname = config.ikeParams.getServerHostname();
        mUseCallerConfiguredNetwork = config.ikeParams.getConfiguredNetwork() != null;

        if (mUseCallerConfiguredNetwork) {
            mNetwork = config.ikeParams.getConfiguredNetwork();
        } else {
            mNetwork = mConnectivityManager.getActiveNetwork();
            if (mNetwork == null) {
                throw new IllegalStateException("No active default network found");
            }
        }

        mNatStatus = NAT_TRAVERSAL_SUPPORT_NOT_CHECKED;
    }

    /** Config includes all configurations to build an IkeConnectionController */
    public static class Config {
        public final IkeContext ikeContext;
        public final IkeSessionParams ikeParams;
        public final IkeLocalAddressGenerator localAddressGenerator;
        public final Callback callback;

        /** Constructor for IkeConnectionController.Config */
        public Config(
                IkeContext ikeContext,
                IkeSessionParams ikeParams,
                IkeLocalAddressGenerator localAddressGenerator,
                Callback callback) {
            this.ikeContext = ikeContext;
            this.ikeParams = ikeParams;
            this.localAddressGenerator = localAddressGenerator;
            this.callback = callback;
        }
    }

    /** Callback to notify status changes of the connection */
    public interface Callback {
        /** Notify the IkeConnectionController caller the underlying network has changed */
        void onUnderlyingNetworkUpdated(boolean isDifferentNetwork, boolean doesServerSupportNatt);

        /** Notify the IkeConnectionController caller that the underlying network died */
        void onUnderlyingNetworkDied(Network network);

        /** Notify the IkeConnectionController caller of the internal error */
        void onError(IkeInternalException exception);
    }

    /** Sets up the IkeConnectionController */
    public void setUp() throws IkeInternalException {
        try {
            resolveAndSetAvailableRemoteAddresses();
            setRemoteAddress();

            int remotePort =
                    mForcePort4500
                            ? IkeSocket.SERVER_PORT_UDP_ENCAPSULATED
                            : IkeSocket.SERVER_PORT_NON_UDP_ENCAPSULATED;
            boolean isIpv4 = mRemoteAddress instanceof Inet4Address;
            mLocalAddress =
                    mIkeLocalAddressGenerator.generateLocalAddress(
                            mNetwork, isIpv4, mRemoteAddress, remotePort);
        } catch (IOException | ErrnoException e) {
            throw new IkeInternalException(e);
        }
    }

    /** Tears down the IkeConnectionController */
    public void tearDown() {
        if (mNetworkCallback != null) {
            mConnectivityManager.unregisterNetworkCallback(mNetworkCallback);
            mNetworkCallback = null;
        }
    }

    /** Updates the underlying network */
    public void setNetwork(Network network) {
        onUnderlyingNetworkUpdated(network);
    }

    /** Gets the underlying network */
    public Network getNetwork() {
        return mNetwork;
    }

    /**
     * Sets the local address.
     *
     * <p>This MUST only be called in a test.
     */
    @VisibleForTesting
    public void setLocalAddress(InetAddress address) {
        mLocalAddress = address;
    }

    /** Gets the local address */
    public InetAddress getLocalAddress() {
        return mLocalAddress;
    }

    /**
     * Sets the remote address.
     *
     * <p>This MUST only be called in a test.
     */
    @VisibleForTesting
    public void setRemoteAddress(InetAddress address) {
        mRemoteAddress = address;
        addRemoteAddress(address);
    }

    /**
     * Adds a remote address.
     *
     * <p>This MUST only be called in a test.
     */
    @VisibleForTesting
    public void addRemoteAddress(InetAddress address) {
        if (address instanceof Inet4Address) {
            mRemoteAddressesV4.add((Inet4Address) address);
        } else {
            mRemoteAddressesV6.add((Inet6Address) address);
        }
    }

    /** Gets the remote addresses */
    public InetAddress getRemoteAddress() {
        return mRemoteAddress;
    }

    /** Gets all the IPv4 remote addresses */
    public List<Inet4Address> getAllRemoteIpv4Addresses() {
        return new ArrayList<>(mRemoteAddressesV4);
    }

    /** Gets all the IPv6 remote addresses */
    public List<Inet6Address> getAllRemoteIpv6Addresses() {
        return new ArrayList<>(mRemoteAddressesV6);
    }

    /**
     * Sets if the server support NAT-T or not.
     *
     * <p>This is method should be called at the first time IKE client sends NAT_DETECTION (in other
     * words the first time IKE client is using IPv4 address since IKE does not support IPv6 NAT-T)
     */
    public void setSeverNattSupport(boolean doesServerSupportNatt) {
        mNatStatus = doesServerSupportNatt ? NAT_TRAVERSAL_SUPPORTED : NAT_TRAVERSAL_UNSUPPORTED;
    }

    /**
     * Clears the knowledge of sever's NAT-T support
     *
     * <p>This MUST only be called in a test.
     */
    @VisibleForTesting
    public void resetSeverNattSupport() {
        mNatStatus = NAT_TRAVERSAL_SUPPORT_NOT_CHECKED;
    }

    /** Returns the NAT status */
    @NatStatus
    public int getNatStatus() {
        return mNatStatus;
    }

    private void resolveAndSetAvailableRemoteAddresses() throws IOException {
        // TODO(b/149954916): Do DNS resolution asynchronously
        InetAddress[] allRemoteAddresses = null;

        for (int attempts = 0;
                attempts < MAX_DNS_RESOLUTION_ATTEMPTS
                        && (allRemoteAddresses == null || allRemoteAddresses.length == 0);
                attempts++) {
            try {
                allRemoteAddresses = mNetwork.getAllByName(mRemoteHostname);
            } catch (UnknownHostException e) {
                final boolean willRetry = attempts + 1 < MAX_DNS_RESOLUTION_ATTEMPTS;
                getIkeLog()
                        .d(
                                TAG,
                                "Failed to look up host for attempt "
                                        + (attempts + 1)
                                        + ": "
                                        + mRemoteHostname
                                        + " retrying? "
                                        + willRetry,
                                e);
            }
        }
        if (allRemoteAddresses == null || allRemoteAddresses.length == 0) {
            throw new IOException(
                    "DNS resolution for "
                            + mRemoteHostname
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
                                + mRemoteAddressesV4
                                + " v6="
                                + mRemoteAddressesV6);

        mRemoteAddressesV4.clear();
        mRemoteAddressesV6.clear();
        for (InetAddress remoteAddress : allRemoteAddresses) {
            if (remoteAddress instanceof Inet4Address) {
                mRemoteAddressesV4.add((Inet4Address) remoteAddress);
            } else {
                mRemoteAddressesV6.add((Inet6Address) remoteAddress);
            }
        }
    }

    /**
     * Set the remote address for the peer.
     *
     * <p>Prefers IPv6 addresses if:
     *
     * <ul>
     *   <li>an IPv6 address is known for the peer, and
     *   <li>the current underlying Network has a global (non-link local) IPv6 address available
     * </ul>
     *
     * Otherwise, an IPv4 address will be used.
     */
    private void setRemoteAddress() {
        LinkProperties linkProperties = mConnectivityManager.getLinkProperties(mNetwork);
        if (!mRemoteAddressesV6.isEmpty() && linkProperties.hasGlobalIpv6Address()) {
            // TODO(b/175348096): randomly choose from available addresses
            mRemoteAddress = mRemoteAddressesV6.get(0);
        } else {
            if (mRemoteAddressesV4.isEmpty()) {
                throw new IllegalArgumentException("No valid IPv4 or IPv6 addresses for peer");
            }

            // TODO(b/175348096): randomly choose from available addresses
            mRemoteAddress = mRemoteAddressesV4.get(0);
        }
    }

    /**
     * Enables IkeConnectionController to handle mobility events
     *
     * <p>This method will enable IkeConnectionController to monitor and handle changes of the
     * underlying network and addresses.
     */
    public void enableMobility() throws IkeInternalException {
        try {
            if (mUseCallerConfiguredNetwork) {
                // Caller configured a specific Network - track it
                // ConnectivityManager does not provide a callback for tracking a specific
                // Network. In order to do so, create a NetworkRequest without any
                // capabilities so it will match all Networks. The NetworkCallback will then
                // filter for the correct (caller-specified) Network.
                NetworkRequest request = new NetworkRequest.Builder().clearCapabilities().build();
                mNetworkCallback = new IkeSpecificNetworkCallback(this, mNetwork, mLocalAddress);
                mConnectivityManager.registerNetworkCallback(
                        request, mNetworkCallback, new Handler(mIkeContext.getLooper()));
            } else {
                // Caller did not configure a specific Network - track the default
                mNetworkCallback = new IkeDefaultNetworkCallback(this, mNetwork, mLocalAddress);
                mConnectivityManager.registerDefaultNetworkCallback(
                        mNetworkCallback, new Handler(mIkeContext.getLooper()));
            }
        } catch (RuntimeException e) {
            // Error occurred while registering the NetworkCallback
            throw new IkeInternalException(e);
        }
    }

    /** Creates a IkeSessionConnectionInfo */
    public IkeSessionConnectionInfo buildIkeSessionConnectionInfo() {
        return new IkeSessionConnectionInfo(mLocalAddress, mRemoteAddress, mNetwork);
    }

    @Override
    public void onUnderlyingNetworkUpdated(Network network) {
        Network oldNetwork = mNetwork;
        InetAddress oldLocalAddress = mLocalAddress;
        InetAddress oldRemoteAddress = mRemoteAddress;

        mNetwork = network;

        // If the network changes, perform a new DNS lookup to ensure that the correct remote
        // address is used. This ensures that DNS returns addresses for the correct address families
        // (important if using a v4/v6-only network). This also ensures that DNS64 is handled
        // correctly when switching between networks that may have different IPv6 prefixes.
        if (!mNetwork.equals(oldNetwork)) {
            try {
                resolveAndSetAvailableRemoteAddresses();
            } catch (IOException e) {
                mCallback.onError(new IkeInternalException(e));
                return;
            }
        }

        setRemoteAddress();

        boolean isIpv4 = mRemoteAddress instanceof Inet4Address;

        // If it is known that the server supports NAT-T, use port 4500. Otherwise, use port 500.
        boolean nattSupported = mNatStatus == NAT_TRAVERSAL_SUPPORTED;
        int serverPort =
                nattSupported
                        ? IkeSocket.SERVER_PORT_UDP_ENCAPSULATED
                        : IkeSocket.SERVER_PORT_NON_UDP_ENCAPSULATED;

        try {
            mLocalAddress =
                    mIkeLocalAddressGenerator.generateLocalAddress(
                            mNetwork, isIpv4, mRemoteAddress, serverPort);
        } catch (ErrnoException | IOException e) {
            mCallback.onError(new IkeInternalException(e));
            return;
        }

        if (mNetwork.equals(oldNetwork)
                && mLocalAddress.equals(oldLocalAddress)
                && mRemoteAddress.equals(oldRemoteAddress)) {
            getIkeLog()
                    .d(
                            TAG,
                            "onUnderlyingNetworkUpdated: None of network, local or remote"
                                    + " address has changed. No action needed here.");
            return;
        }

        mNetworkCallback.setNetwork(mNetwork);
        mNetworkCallback.setAddress(mLocalAddress);

        // TODO: Update IkeSocket and NATT keepalive

        mCallback.onUnderlyingNetworkUpdated(!mNetwork.equals(oldNetwork), nattSupported);
    }

    @Override
    public void onUnderlyingNetworkDied() {
        mCallback.onUnderlyingNetworkDied(mNetwork);
    }
}
