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

package com.android.internal.net.ipsec.ike.net;

import android.net.LinkProperties;
import android.net.Network;

import java.net.InetAddress;

/**
 * IkeDefaultNetworkCallback is a network callback used to track the application default Network.
 *
 * <p>This NetworkCallback will notify IkeNetworkUpdater if:
 *
 * <ul>
 *   <li>the default Network changes, or
 *   <li>the local Address for the default Network is dropped,
 *   <li>the default Network dies with no alternatives available.
 * </ul>
 *
 * <p>In the case of default Network changes, the IkeNetworkUpdater will be notified after
 * onLinkPropertiesChanged is called.
 *
 * <p>MUST be registered with {@link android.net.ConnectivityManager} and specify the
 * IkeSessionStateMachine's Handler to prevent races.
 */
public class IkeDefaultNetworkCallback extends IkeNetworkCallbackBase {
    public IkeDefaultNetworkCallback(
            IkeNetworkUpdater ikeNetworkUpdater, Network currNetwork, InetAddress currAddress) {
        super(ikeNetworkUpdater, currNetwork, currAddress);
    }

    /**
     * This method will be called either on the current default network or after {@link
     * #onAvailable(Network)} when a new default network is brought up.
     */
    @Override
    public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
        logd("onLinkPropertiesChanged: " + network);

        if (!mCurrNetwork.equals(network)) {
            mCurrNetwork = network;
            logd("Application default Network changed to " + network);
            mIkeNetworkUpdater.onUnderlyingNetworkUpdated(network, linkProperties);
        } else if (isCurrentAddressLost(linkProperties)) {
            mIkeNetworkUpdater.onUnderlyingNetworkUpdated(network, linkProperties);
        }
    }
}
