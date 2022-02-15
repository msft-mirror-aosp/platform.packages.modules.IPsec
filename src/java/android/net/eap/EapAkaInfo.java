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

package android.net.eap;

import android.annotation.NonNull;
import android.annotation.Nullable;

import com.android.internal.annotations.VisibleForTesting;

import java.util.Objects;

/**
 * EapAkaInfo represents a container for EAP AKA information
 * during Authentication.
 *
 * @hide
 */
public class EapAkaInfo extends EapInfo {
    /**
     * Re-authentication ID for next use
     *
     * <p>This identity encoding MUST follow the UTF-8 transformation format[RFC3629].
     *
     * @hide
     */
    private final byte[] mReauthId;

    /** @hide */
    @VisibleForTesting
    public EapAkaInfo(int eapType, @Nullable byte[] reauthId) {
        super(eapType);
        mReauthId = reauthId;
    }

    private EapAkaInfo(Builder builder) {
        super(builder.mEapMethodType);
        mReauthId = builder.mReauthId;
    }

    /**
     * Retrieves re-authentication ID from server for next use.
     *
     * @return re-authentication ID
     *
     * @hide
     */
    @Nullable
    public byte[] getReauthId() {
        return mReauthId;
    }

    /**
     * This class can be used to incrementally construct an {@link EapAkaInfo}.
     *
     * @hide
     */
    public static final class Builder {
        private int mEapMethodType;
        private byte[] mReauthId;

        /**
         * Constructs and returns a new Builder for constructing an {@link EapAkaInfo}.
         *
         * @param eapType EAP type
         *
         * @hide
         */
        public Builder(int eapType) {
            mEapMethodType = eapType;
        }

        /**
         * Sets the re-authentication ID for next use.
         *
         * @param reauthId byte[] representing the client's EAP Identity.
         * @return Builder this, to facilitate chaining.
         *
         * @hide
         */
        @NonNull
        public Builder setReauthId(@NonNull byte[] reauthId) {
            Objects.requireNonNull(reauthId, "reauthId must not be null");
            this.mReauthId = new byte[reauthId.length];
            System.arraycopy(reauthId, 0, this.mReauthId, 0, reauthId.length);
            return this;
        }

        /**
         * Constructs and returns an EapAkaInfo with the information applied to this
         * Builder.
         *
         * @return the EapAkaInfo constructed by this Builder.
         *
         * @hide
         */
        @NonNull
        public EapAkaInfo build() {
            return new EapAkaInfo(this);
        }
    }
}
