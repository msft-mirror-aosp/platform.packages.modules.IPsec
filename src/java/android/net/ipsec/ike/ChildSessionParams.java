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

import android.annotation.NonNull;
import android.annotation.SystemApi;

import libcore.net.InetAddressUtils;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * ChildSessionParams is an abstract class that represents proposed configurations for negotiating a
 * Child Session.
 *
 * <p>Note that references to negotiated configurations will be held, and the same parameters will
 * be reused during rekey. This includes SA Proposals, lifetimes and traffic selectors.
 *
 * @see {@link TunnelModeChildSessionParams} and {@link TransportModeChildSessionParams}
 * @hide
 */
@SystemApi
public abstract class ChildSessionParams {
    @NonNull private static final IkeTrafficSelector DEFAULT_TRAFFIC_SELECTOR_IPV4;
    // TODO: b/130765172 Add TRAFFIC_SELECTOR_IPV6 and instantiate it.

    static {
        DEFAULT_TRAFFIC_SELECTOR_IPV4 =
                buildDefaultTrafficSelector(
                        IkeTrafficSelector.TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE);
    }

    @NonNull private final IkeTrafficSelector[] mLocalTrafficSelectors;
    @NonNull private final IkeTrafficSelector[] mRemoteTrafficSelectors;
    @NonNull private final ChildSaProposal[] mSaProposals;
    private final boolean mIsTransport;

    /** @hide */
    protected ChildSessionParams(
            IkeTrafficSelector[] localTs,
            IkeTrafficSelector[] remoteTs,
            ChildSaProposal[] proposals,
            boolean isTransport) {
        mLocalTrafficSelectors = localTs;
        mRemoteTrafficSelectors = remoteTs;
        mSaProposals = proposals;
        mIsTransport = isTransport;
    }

    /** Retrieves configured local (client) traffic selectors */
    @NonNull
    public List<IkeTrafficSelector> getLocalTrafficSelectors() {
        return Arrays.asList(mLocalTrafficSelectors);
    }

    /** Retrieves configured remote (server) traffic selectors */
    @NonNull
    public List<IkeTrafficSelector> getRemoteTrafficSelectors() {
        return Arrays.asList(mRemoteTrafficSelectors);
    }

    /** Retrieves all ChildSaProposals configured */
    @NonNull
    public List<ChildSaProposal> getSaProposals() {
        return Arrays.asList(mSaProposals);
    }

    /** @hide */
    public IkeTrafficSelector[] getLocalTrafficSelectorsInternal() {
        return mLocalTrafficSelectors;
    }

    /** @hide */
    public IkeTrafficSelector[] getRemoteTrafficSelectorsInternal() {
        return mRemoteTrafficSelectors;
    }

    /** @hide */
    public ChildSaProposal[] getSaProposalsInternal() {
        return mSaProposals;
    }

    /** @hide */
    public boolean isTransportMode() {
        return mIsTransport;
    }

    /**
     * This class represents common information for Child Session Parameters Builders.
     *
     * @hide
     */
    protected abstract static class Builder {
        @NonNull protected final List<IkeTrafficSelector> mLocalTsList = new LinkedList<>();
        @NonNull protected final List<IkeTrafficSelector> mRemoteTsList = new LinkedList<>();
        @NonNull protected final List<SaProposal> mSaProposalList = new LinkedList<>();

        protected Builder() {
            // Currently IKE library only accepts setting up Child SA that all ports and all
            // addresses are allowed on both sides. The protected traffic range is determined by the
            // socket or interface that the {@link IpSecTransform} is applied to.
            // TODO: b/130756765 Validate the current TS negotiation strategy.
            mLocalTsList.add(DEFAULT_TRAFFIC_SELECTOR_IPV4);
            mRemoteTsList.add(DEFAULT_TRAFFIC_SELECTOR_IPV4);
            // TODO: add IPv6 TS to ChildSessionParams.
        }

        protected void validateAndAddSaProposal(@NonNull ChildSaProposal proposal) {
            mSaProposalList.add(proposal);
        }

        protected void validateOrThrow() {
            if (mSaProposalList.isEmpty()) {
                throw new IllegalArgumentException(
                        "ChildSessionParams requires at least one Child SA proposal.");
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
