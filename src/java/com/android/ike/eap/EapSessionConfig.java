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

package com.android.ike.eap;

import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;

import com.android.ike.eap.message.EapData.EapMethod;
import com.android.internal.annotations.VisibleForTesting;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * EapSessionConfig represents a container for EAP method configs to be used within an IKEv2
 * session.
 *
 * <p>The EAP authentication server decides which EAP method is used, so clients are encouraged to
 * provide configs for several EAP methods.
 */
public final class EapSessionConfig {
    // IANA -> EapMethodConfig for that method
    public final Map<Integer, EapMethodConfig> eapConfigs;
    public final byte[] eapIdentity;

    @VisibleForTesting
    EapSessionConfig(Map<Integer, EapMethodConfig> eapConfigs, byte[] eapIdentity) {
        this.eapConfigs = Collections.unmodifiableMap(eapConfigs);
        this.eapIdentity = eapIdentity;
    }

    /** This class can be used to incrementally construct an EapSessionConfig. */
    public static final class Builder {
        private final Map<Integer, EapMethodConfig> mEapConfigs;
        private byte[] mEapIdentity;

        /**
         * Constructs and returns a new Builder for constructing an EapSessionConfig.
         */
        public Builder() {
            mEapConfigs = new HashMap<>();
            mEapIdentity = new byte[0];
        }

        /**
         * Sets the client's EAP Identity.
         *
         * @param eapIdentity byte[] representing the client's EAP Identity
         * @return Builder this, to facilitate chaining.
         */
        public Builder setEapIdentity(byte[] eapIdentity) {
            this.mEapIdentity = eapIdentity.clone();
            return this;
        }

        /**
         * Sets the configuration for EAP SIM.
         *
         * @param subId int the client's subId to be authenticated
         * @return Builder this, to facilitate chaining.
         */
        public Builder setEapSimConfig(int subId) {
            mEapConfigs.put(EAP_TYPE_SIM, new EapSimConfig(subId));
            return this;
        }

        /**
         * Constructs and returns an EapSessionConfig with the configurations applied to this
         * Builder.
         *
         * @return the EapSessionConfig constructed by this Builder
         * @throws IllegalStateException iff no EAP methods have been configured
         */
        public EapSessionConfig build() {
            if (mEapConfigs.isEmpty()) {
                throw new IllegalStateException("Must have at least one EAP method configured");
            }

            return new EapSessionConfig(mEapConfigs, mEapIdentity);
        }
    }

    /** EapMethodConfig represents a generic EAP method configuration. */
    public abstract static class EapMethodConfig {
        @EapMethod public final int methodType;

        protected EapMethodConfig(@EapMethod int methodType) {
            this.methodType = methodType;
        }
    }

    private abstract static class EapUiccConfig extends EapMethodConfig {
        public final int subId;

        private EapUiccConfig(@EapMethod int methodType, int subId) {
            super(methodType);
            this.subId = subId;
        }
    }

    /**
     * EapSimConfig represents the configs needed for an EAP SIM session.
     */
    public static class EapSimConfig extends EapUiccConfig {
        @VisibleForTesting
        public EapSimConfig(int subId) {
            super(EAP_TYPE_SIM, subId);
        }
    }
}
