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

package com.android.internal.net.ipsec.ike;

import android.net.Network;

import java.io.FileDescriptor;
import java.io.IOException;
import java.util.Objects;

/**
 * IkeSocketConfig represents a socket configuration.
 *
 * <p>IkeSessionStateMachines that share the same socket configuration and request the same IKE
 * socket type (v4, v6, v4-encap, v6-encap-port) will be sharing the same IkeSocket instance.
 */

// TODO: b/178420172. Adding DSCP value in this class
public final class IkeSocketConfig {
    // Network that the IKE socket will be bound to.
    private final Network mNetwork;

    /** Construct an IkeSocketConfig. */
    public IkeSocketConfig(Network network) {
        mNetwork = network;
    }

    /** Returns the underlying network. */
    public Network getNetwork() {
        return mNetwork;
    }

    /** Applies the socket configuration to the input socket. */
    public void applyTo(FileDescriptor sock) throws IOException {
        mNetwork.bindSocket(sock);
    }

    /** @hide */
    @Override
    public int hashCode() {
        return Objects.hash(mNetwork);
    }

    /** @hide */
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IkeSocketConfig)) {
            return false;
        }

        IkeSocketConfig other = (IkeSocketConfig) o;

        return mNetwork.equals(other.mNetwork);
    }
}
