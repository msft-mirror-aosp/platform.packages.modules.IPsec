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

import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_ADDRESS;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_NETMASK;
import static com.android.internal.net.ipsec.ike.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_ADDRESS;

import android.annotation.NonNull;
import android.annotation.SystemApi;
import android.net.IpPrefix;
import android.net.LinkAddress;

import com.android.internal.net.ipsec.ike.message.IkeConfigPayload;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Address;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv4Netmask;
import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Address;

import java.net.InetAddress;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * ChildSessionConfiguration represents the negotiated configuration for a Child Session.
 *
 * <p>Configurations include traffic selectors and internal network information.
 *
 * @hide
 */
@SystemApi
public final class ChildSessionConfiguration {
    private static final int IPv4_DEFAULT_PREFIX_LEN = 32;

    private final List<IkeTrafficSelector> mInboundTs;
    private final List<IkeTrafficSelector> mOutboundTs;
    private final List<LinkAddress> mInternalAddressList;

    /**
     * Construct an instance of {@link ChildSessionConfiguration}.
     *
     * <p>It is only supported to build a {@link ChildSessionConfiguration} with a Configure(Reply)
     * Payload.
     *
     * @hide
     */
    public ChildSessionConfiguration(
            List<IkeTrafficSelector> inTs,
            List<IkeTrafficSelector> outTs,
            IkeConfigPayload configPayload) {
        this(inTs, outTs);

        if (configPayload.configType != IkeConfigPayload.CONFIG_TYPE_REPLY) {
            throw new IllegalArgumentException(
                    "Cannot build ChildSessionConfiguration with configuration type: "
                            + configPayload.configType);
        }

        // It is validated in IkeConfigPayload that a config reply only has at most one non-empty
        // netmask and netmask exists only when IPv4 internal address exists.
        ConfigAttributeIpv4Netmask netmaskAttr = null;
        for (ConfigAttribute att : configPayload.recognizedAttributeList) {
            if (att.attributeType == CONFIG_ATTR_INTERNAL_IP4_NETMASK && !att.isEmptyValue()) {
                netmaskAttr = (ConfigAttributeIpv4Netmask) att;
            }
        }

        for (ConfigAttribute att : configPayload.recognizedAttributeList) {
            if (att.isEmptyValue()) continue;
            switch (att.attributeType) {
                case CONFIG_ATTR_INTERNAL_IP4_ADDRESS:
                    ConfigAttributeIpv4Address addressAttr = (ConfigAttributeIpv4Address) att;
                    if (netmaskAttr != null) {
                        mInternalAddressList.add(
                                new LinkAddress(addressAttr.address, netmaskAttr.getPrefixLen()));
                    } else {
                        mInternalAddressList.add(
                                new LinkAddress(addressAttr.address, IPv4_DEFAULT_PREFIX_LEN));
                    }
                    break;
                case CONFIG_ATTR_INTERNAL_IP4_NETMASK:
                    // No action.
                    break;
                case CONFIG_ATTR_INTERNAL_IP6_ADDRESS:
                    mInternalAddressList.add(((ConfigAttributeIpv6Address) att).linkAddress);
                    break;
                default:
                    // TODO: Support DNS,Subnet and Dhcp4 attributes
            }
        }
    }

    /**
     * Construct an instance of {@link ChildSessionConfiguration}.
     *
     * @hide
     */
    public ChildSessionConfiguration(
            List<IkeTrafficSelector> inTs, List<IkeTrafficSelector> outTs) {
        mInboundTs = Collections.unmodifiableList(inTs);
        mOutboundTs = Collections.unmodifiableList(outTs);
        mInternalAddressList = new LinkedList<>();
    }

    /**
     * Returns the negotiated inbound traffic selectors.
     *
     * <p>Only inbound traffic within the range is acceptable to the Child Session.
     *
     * <p>The Android platform does not support port-based routing. Port ranges of traffic selectors
     * are only informational.
     *
     * @return the inbound traffic selectors.
     */
    @NonNull
    public List<IkeTrafficSelector> getInboundTrafficSelectors() {
        return mInboundTs;
    }

    /**
     * Returns the negotiated outbound traffic selectors.
     *
     * <p>Only outbound traffic within the range is acceptable to the Child Session.
     *
     * <p>The Android platform does not support port-based routing. Port ranges of traffic selectors
     * are only informational.
     *
     * @return the outbound traffic selectors.
     */
    @NonNull
    public List<IkeTrafficSelector> getOutboundTrafficSelectors() {
        return mOutboundTs;
    }

    /**
     * Returns the assigned internal addresses.
     *
     * @return the assigned internal addresses, or an empty list when no addresses are assigned by
     *     the remote IKE server (e.g. for a non-tunnel mode Child Session).
     */
    @NonNull
    public List<LinkAddress> getInternalAddresses() {
        return mInternalAddressList;
    }

    /**
     * Returns the internal subnets protected by the IKE server.
     *
     * @return the internal subnets, or an empty list when no information of protected subnets is
     *     provided by the IKE server (e.g. for a non-tunnel mode Child Session).
     */
    @NonNull
    public List<IpPrefix> getInternalSubnets() {
        // TODO: Implement it.
        throw new UnsupportedOperationException("Not yet supported");
    }

    /**
     * Returns the internal DNS server addresses.
     *
     * @return the internal DNS server addresses, or an empty list when no DNS server is provided by
     *     the IKE server (e.g. for a non-tunnel mode Child Session).
     */
    @NonNull
    public List<InetAddress> getInternalDnsServers() {
        // TODO: Implement it.
        throw new UnsupportedOperationException("Not yet supported");
    }

    /**
     * Returns the internal DHCP server addresses.
     *
     * @return the internal DHCP server addresses, or an empty list when no DHCP server is provided
     *     by the IKE server (e.g. for a non-tunnel mode Child Session).
     */
    @NonNull
    public List<InetAddress> getInternalDhcpServers() {
        // TODO: Implement it.
        throw new UnsupportedOperationException("Not yet supported");
    }
}
