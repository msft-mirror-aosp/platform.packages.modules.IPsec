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


import libcore.net.InetAddressUtils;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.List;

/**
 * This abstract class is the superclass of all classes representing a set of user configurations
 * for Child Session negotiation.
 */
public abstract class ChildSessionOptions {
    private static final IkeTrafficSelector DEFAULT_TRAFFIC_SELECTOR_IPV4;
    // TODO: b/130765172 Add TRAFFIC_SELECTOR_IPV6 and instantiate it.

    static {
        DEFAULT_TRAFFIC_SELECTOR_IPV4 =
                buildDefaultTrafficSelector(
                        IkeTrafficSelector.TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE);
    }

    private final IkeTrafficSelector[] mLocalTrafficSelectors;
    private final IkeTrafficSelector[] mRemoteTrafficSelectors;
    private final ChildSaProposal[] mSaProposals;
    private final boolean mIsTransport;

    protected ChildSessionOptions(
            IkeTrafficSelector[] localTs,
            IkeTrafficSelector[] remoteTs,
            ChildSaProposal[] proposals,
            boolean isTransport) {
        mLocalTrafficSelectors = localTs;
        mRemoteTrafficSelectors = remoteTs;
        mSaProposals = proposals;
        mIsTransport = isTransport;
    }

    /** Package private */
    IkeTrafficSelector[] getLocalTrafficSelectors() {
        return mLocalTrafficSelectors;
    }

    /** Package private */
    IkeTrafficSelector[] getRemoteTrafficSelectors() {
        return mRemoteTrafficSelectors;
    }

    /** Package private */
    ChildSaProposal[] getSaProposals() {
        return mSaProposals;
    }

    /** Package private */
    boolean isTransportMode() {
        return mIsTransport;
    }

    /** This class represents common information for Child Sesison Options Builders. */
    protected abstract static class Builder {
        protected final List<IkeTrafficSelector> mLocalTsList = new LinkedList<>();
        protected final List<IkeTrafficSelector> mRemoteTsList = new LinkedList<>();
        protected final List<SaProposal> mSaProposalList = new LinkedList<>();

        protected Builder() {
            // Currently IKE library only accepts setting up Child SA that all ports and all
            // addresses are allowed on both sides. The protected traffic range is determined by the
            // socket or interface that the {@link IpSecTransform} is applied to.
            // TODO: b/130756765 Validate the current TS negotiation strategy.
            mLocalTsList.add(DEFAULT_TRAFFIC_SELECTOR_IPV4);
            mRemoteTsList.add(DEFAULT_TRAFFIC_SELECTOR_IPV4);
            // TODO: add IPv6 TS to ChildSessionOptions.
        }

        protected void validateAndAddSaProposal(ChildSaProposal proposal) {
            mSaProposalList.add(proposal);
        }

        protected void validateOrThrow() {
            if (mSaProposalList.isEmpty()) {
                throw new IllegalArgumentException(
                        "ChildSessionOptions requires at least one Child SA proposal.");
            }
        }
    }

    private static IkeTrafficSelector buildDefaultTrafficSelector(
            @IkeTrafficSelector.TrafficSelectorType int tsType) {
        int startPort = IkeTrafficSelector.PORT_NUMBER_MIN;
        int endPort = IkeTrafficSelector.PORT_NUMBER_MAX;
        InetAddress startAddress = null;
        InetAddress endAddress = null;
        switch (tsType) {
            case IkeTrafficSelector.TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE:
                startAddress = InetAddressUtils.parseNumericAddress("0.0.0.0");
                endAddress = InetAddressUtils.parseNumericAddress("255.255.255.255");
                break;
            case IkeTrafficSelector.TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE:
                // TODO: Support it.
                throw new UnsupportedOperationException("Do not support IPv6.");
            default:
                throw new IllegalArgumentException("Invalid Traffic Selector type: " + tsType);
        }

        return new IkeTrafficSelector(tsType, startPort, endPort, startAddress, endAddress);
    }
}
