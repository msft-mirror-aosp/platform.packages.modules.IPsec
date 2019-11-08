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

package com.android.ike.ikev2;

import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_ADDRESS;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP4_NETMASK;
import static com.android.ike.ikev2.message.IkeConfigPayload.CONFIG_ATTR_INTERNAL_IP6_ADDRESS;

import android.net.LinkAddress;

import com.android.ike.ikev2.message.IkeConfigPayload;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttribute;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Address;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv4Netmask;
import com.android.ike.ikev2.message.IkeConfigPayload.ConfigAttributeIpv6Address;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/** ChildSessionConfiguration represents the negotiated configuration for a Child Session. */
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

    /** Construct an instance of {@link ChildSessionConfiguration}. */
    public ChildSessionConfiguration(
            List<IkeTrafficSelector> inTs, List<IkeTrafficSelector> outTs) {
        mInboundTs = Collections.unmodifiableList(inTs);
        mOutboundTs = Collections.unmodifiableList(outTs);
        mInternalAddressList = new LinkedList<>();
    }

    /**
     * Returns the negotiated inbound traffic selectors.
     *
     * @return the inbound traffic selector.
     */
    public List<IkeTrafficSelector> getInboundTrafficSelectors() {
        return mInboundTs;
    }

    /**
     * Returns the negotiated outbound traffic selectors.
     *
     * @return the outbound traffic selector.
     */
    public List<IkeTrafficSelector> getOutboundTrafficSelectors() {
        return mOutboundTs;
    }

    /**
     * Returns the assigned internal addresses.
     *
     * @return assigned internal addresses, or empty list when no addresses are assigned by the
     *     remote IKE server.
     */
    public List<LinkAddress> getInternalAddressList() {
        return mInternalAddressList;
    }
}
