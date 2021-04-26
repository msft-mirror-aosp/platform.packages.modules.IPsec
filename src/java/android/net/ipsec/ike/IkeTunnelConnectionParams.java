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

package android.net.ipsec.ike;

import android.annotation.NonNull;
import android.annotation.SuppressLint;
import android.net.TunnelConnectionParams;

import java.util.Objects;

/**
 * IkeTunnelConnectionParams contains IKEv2 configurations to establish an IKE/IPsec tunnel.
 *
 * <p>This class is an extension of the {@link TunnelConnectionParams}, containing IKEv2-specific
 * configuration, authentication and authorization parameters.
 *
 * @see TunnelConnectionParams
 */
// TODO: b/186071626 Remove TunnelConnectionParams when non-updatable API stub can resolve
// IkeTunnelConnectionParams.
// TODO:b/185579441 Annotate this class with @RequiresApi(Build.VERSION_CODES.S) if it still
// inherits TunnelConnectionParams when
// @RequiresApi issue is fixed.
@SuppressLint("NewApi")
public final class IkeTunnelConnectionParams implements TunnelConnectionParams {
    private final IkeSessionParams mIkeParams;
    private final TunnelModeChildSessionParams mChildParams;

    /**
     * Construct an IkeTunnelConnectionParams instance.
     *
     * @param ikeParams the IKE Session configuration
     * @param childParams the Tunnel mode Child Session configuration
     */
    public IkeTunnelConnectionParams(
            @NonNull IkeSessionParams ikeParams,
            @NonNull TunnelModeChildSessionParams childParams) {
        Objects.requireNonNull(ikeParams, "ikeParams was null");
        Objects.requireNonNull(childParams, "childParams was null");

        mIkeParams = ikeParams;
        mChildParams = childParams;
    }

    /** Returns the IKE Session configuration. */
    @NonNull
    public IkeSessionParams getIkeSessionParams() {
        return mIkeParams;
    }

    /** Returns the Tunnel mode Child Session configuration. */
    @NonNull
    public TunnelModeChildSessionParams getTunnelModeChildSessionParams() {
        return mChildParams;
    }

    /** @hide */
    @Override
    public int hashCode() {
        return Objects.hash(mIkeParams, mChildParams);
    }

    /** @hide */
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IkeTunnelConnectionParams)) {
            return false;
        }

        IkeTunnelConnectionParams other = (IkeTunnelConnectionParams) o;

        return Objects.equals(mIkeParams, other.mIkeParams)
                && Objects.equals(mChildParams, other.mChildParams);
    }
}
