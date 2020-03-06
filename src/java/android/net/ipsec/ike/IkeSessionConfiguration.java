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

package android.net.ipsec.ike;

import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_IP4_PCSCF;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_IP6_PCSCF;

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.SystemApi;

import com.android.internal.net.ipsec.ike.message.IkeConfigPayload;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Pcscf;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Pcscf;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * IkeSessionConfiguration represents the negotiated configuration for a {@link IkeSession}.
 *
 * <p>Configurations include remote application version and enabled IKE extensions..
 *
 * @hide
 */
@SystemApi
public final class IkeSessionConfiguration {
    /** @hide */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({EXTENSION_TYPE_FRAGMENTATION, EXTENSION_TYPE_MOBIKE})
    public @interface ExtensionType {}

    /** IKE Message Fragmentation */
    public static final int EXTENSION_TYPE_FRAGMENTATION = 1;
    /** IKEv2 Mobility and Multihoming Protocol */
    public static final int EXTENSION_TYPE_MOBIKE = 2;

    private final IkeSessionConnectionInfo mIkeConnInfo;
    private final List<InetAddress> mPcscfServers = new ArrayList<>();

    /**
     * Construct an instance of {@link IkeSessionConfiguration}.
     *
     * <p>IkeSessionConfigurations may only be built with a with a Configure(Reply) Payload.
     *
     * @hide
     */
    public IkeSessionConfiguration(
            IkeSessionConnectionInfo ikeConnInfo, IkeConfigPayload configPayload) {
        // TODO(b/150466460): Throw exception if ikeConnInfo is null
        mIkeConnInfo = ikeConnInfo;

        if (configPayload != null) {
            if (configPayload.configType != IkeConfigPayload.CONFIG_TYPE_REPLY) {
                throw new IllegalArgumentException(
                        "Cannot build IkeSessionConfiguration with configuration type: "
                                + configPayload.configType);
            }

            for (ConfigAttribute attr : configPayload.recognizedAttributeList) {
                if (attr.isEmptyValue()) continue;
                switch (attr.attributeType) {
                    case CONFIG_ATTR_IP4_PCSCF:
                        ConfigAttributeIpv4Pcscf ip4Pcscf = (ConfigAttributeIpv4Pcscf) attr;
                        mPcscfServers.add(ip4Pcscf.getAddress());
                        break;
                    case CONFIG_ATTR_IP6_PCSCF:
                        ConfigAttributeIpv6Pcscf ip6Pcscf = (ConfigAttributeIpv6Pcscf) attr;
                        mPcscfServers.add(ip6Pcscf.getAddress());
                        break;
                    default:
                        // Not relevant to IKE session
                }
            }
        }
    }

    /**
     * Gets remote (server) version information.
     *
     * @return application version of the remote server, or an empty string if the remote server did
     *     not provide the application version.
     */
    @NonNull
    public String getRemoteApplicationVersion() {
        // TODO: Implement it.
        throw new UnsupportedOperationException("Not yet supported");
    }

    /**
     * Returns remote vendor IDs received during IKE Session setup.
     *
     * @return the vendor IDs of the remote server, or an empty list if no vendor ID is received
     *     during IKE Session setup.
     */
    @NonNull
    public List<byte[]> getRemoteVendorIDs() {
        // TODO: Implement it.
        throw new UnsupportedOperationException("Not yet supported");
    }

    /**
     * Checks if an IKE extension is enabled.
     *
     * <p>An IKE extension is enabled when both sides can support it. This negotiation always
     * happens in IKE initial exchanges (IKE INIT and IKE AUTH).
     *
     * @param extensionType the extension type.
     * @return {@code true} if this extension is enabled.
     */
    public boolean isIkeExtensionEnabled(@ExtensionType int extensionType) {
        // TODO: Implement it.
        throw new UnsupportedOperationException("Not yet supported");
    }

    /**
     * Returns the assigned P_CSCF servers.
     *
     * @return the assigned P_CSCF servers, or an empty list when no servers are assigned by the
     *     remote IKE server
     */
    @NonNull
    public List<InetAddress> getPcscfServers() {
        return Collections.unmodifiableList(mPcscfServers);
    }

    /**
     * Returns the connection information.
     *
     * @return the IKE Session connection information.
     * @hide
     */
    @NonNull
    public IkeSessionConnectionInfo getIkeSessionConnectionInfo() {
        return mIkeConnInfo;
    }
}
