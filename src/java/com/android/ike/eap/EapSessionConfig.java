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

import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapData.EAP_TYPE_MSCHAP_V2;
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;

import android.telephony.TelephonyManager.UiccAppType;

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
    @VisibleForTesting
    static final byte[] DEFAULT_IDENTITY = new byte[0];

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
            mEapIdentity = DEFAULT_IDENTITY;
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
         * @param apptype the {@link UiccAppType} apptype to be used for authentication
         * @return Builder this, to facilitate chaining.
         */
        public Builder setEapSimConfig(int subId, @UiccAppType int apptype) {
            mEapConfigs.put(EAP_TYPE_SIM, new EapSimConfig(subId, apptype));
            return this;
        }

        /**
         * Sets the configuration for EAP AKA.
         *
         * @param subId int the client's subId to be authenticated
         * @param apptype the {@link UiccAppType} apptype to be used for authentication
         * @return Builder this, to facilitate chaining
         */
        public Builder setEapAkaConfig(int subId, @UiccAppType int apptype) {
            mEapConfigs.put(EAP_TYPE_AKA, new EapAkaConfig(subId, apptype));
            return this;
        }

        /**
         * Sets the configuration for EAP MSCHAPv2.
         *
         * @param username String the client account's username to be authenticated
         * @param password String the client account's password to be authenticated
         * @return Builder this, to faciliate chaining
         */
        public Builder setEapMsChapV2Config(String username, String password) {
            mEapConfigs.put(EAP_TYPE_MSCHAP_V2, new EapMsChapV2Config(username, password));
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

    /**
     * EapUiccConfig represents the configs needed for EAP methods that rely on UICC cards for
     * authentication.
     */
    public abstract static class EapUiccConfig extends EapMethodConfig {
        public final int subId;
        public final int apptype;

        private EapUiccConfig(@EapMethod int methodType, int subId, @UiccAppType int apptype) {
            super(methodType);
            this.subId = subId;
            this.apptype = apptype;
        }
    }

    /**
     * EapSimConfig represents the configs needed for an EAP SIM session.
     */
    public static class EapSimConfig extends EapUiccConfig {
        @VisibleForTesting
        public EapSimConfig(int subId, @UiccAppType int apptype) {
            super(EAP_TYPE_SIM, subId, apptype);
        }
    }

    /**
     * EapAkaConfig represents the configs needed for an EAP AKA session.
     */
    public static class EapAkaConfig extends EapUiccConfig {
        @VisibleForTesting
        public EapAkaConfig(int subId, @UiccAppType int apptype) {
            super(EAP_TYPE_AKA, subId, apptype);
        }
    }

    /**
     * EapMsChapV2Config represents the configs needed for an EAP MSCHAPv2 session.
     */
    public static class EapMsChapV2Config extends EapMethodConfig {
        public final String username;
        public final String password;

        private EapMsChapV2Config(String username, String password) {
            super(EAP_TYPE_MSCHAP_V2);

            this.username = username;
            this.password = password;
        }
    }
}
