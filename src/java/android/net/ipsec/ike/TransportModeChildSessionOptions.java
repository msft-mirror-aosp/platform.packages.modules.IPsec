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

/**
 * This class contains all user provided configuration options for negotiating a transport mode
 * Child Session.
 */
public final class TransportModeChildSessionOptions extends ChildSessionOptions {
    private TransportModeChildSessionOptions(
            IkeTrafficSelector[] localTs,
            IkeTrafficSelector[] remoteTs,
            ChildSaProposal[] proposals) {
        super(localTs, remoteTs, proposals, true /*isTransport*/);
    }

    /** This class can be used to incrementally construct a TransportModeChildSessionOptions. */
    public static final class Builder extends ChildSessionOptions.Builder {
        /** Create a Builder for negotiating a transport mode Child Session. */
        public Builder() {
            super();
        }

        /**
         * Adds an Child SA proposal to TransportModeChildSessionOptions being built.
         *
         * @param proposal Child SA proposal.
         * @return Builder this, to facilitate chaining.
         * @throws IllegalArgumentException if input proposal is not a Child SA proposal.
         */
        public Builder addSaProposal(@NonNull ChildSaProposal proposal) {
            validateAndAddSaProposal(proposal);
            return this;
        }

        /**
         * Validates, builds and returns the TransportModeChildSessionOptions.
         *
         * @return the validated TransportModeChildSessionOptions.
         * @throws IllegalArgumentException if no Child SA proposal is provided.
         */
        public TransportModeChildSessionOptions build() {
            validateOrThrow();

            return new TransportModeChildSessionOptions(
                    mLocalTsList.toArray(new IkeTrafficSelector[mLocalTsList.size()]),
                    mRemoteTsList.toArray(new IkeTrafficSelector[mRemoteTsList.size()]),
                    mSaProposalList.toArray(new ChildSaProposal[mSaProposalList.size()]));
        }
    }
}
