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

package android.net.ipsec.ike.exceptions;

import android.net.Network;
import android.net.ipsec.ike.IkeSessionCallback;

import java.util.Objects;

/**
 * IkeNetworkDiedException is returned to the caller via {@link
 * IkeSessionCallback#onError(IkeException)} if the underlying Network for the {@link IkeSession}
 * dies with no alternatives.
 *
 * <p>When the caller receives this Exception, they must either:
 *
 * <ul>
 *   <li>set a new underlying Network for the corresponding IkeSession (MOBIKE must be enabled and
 *       the IKE Session must have started with a caller-configured Network), or
 *   <li>close the corresponding IkeSession.
 * </ul>
 *
 * @hide
 */
public final class IkeNetworkDiedException extends IkeException {
    private final Network mNetwork;

    public IkeNetworkDiedException(Network network) {
        super();
        Objects.requireNonNull(network, "network is null");

        mNetwork = network;
    }

    public IkeNetworkDiedException(Network network, String message) {
        super(message);
        Objects.requireNonNull(network, "network is null");

        mNetwork = network;
    }

    /** Returns the IkeSession's underlying Network that died. */
    public Network getNetwork() {
        return mNetwork;
    }
}
