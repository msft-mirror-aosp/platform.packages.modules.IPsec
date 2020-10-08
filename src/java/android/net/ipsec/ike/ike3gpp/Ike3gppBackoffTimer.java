/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.net.ipsec.ike.ike3gpp;

import android.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Class representing the data provided by the peer for a BACKOFF_TIMER payload.
 *
 * @see TS 24.302 Section 8.2.9.1 BACKOFF_TIMER Notify Payload
 * @hide
 */
public final class Ike3gppBackoffTimer extends Ike3gppInfo {
    /**
     * Notify Error indicating that the requested APN is not included in the user's profile, so
     * access is not authorized.
     *
     * <p>Note that this is not an IANA-specified value.
     *
     * <p>Corresponds to DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION Result code IE as specified in 3GPP
     * TS 29.273 Section 10.3.7
     */
    public static final int NOTIFY_ERROR_NO_APN_SUBSCRIPTION = 9002;

    /**
     * Notify Error indicating that the procedure can't be completed due to network failure.
     *
     * <p>Note that this is not an IANA-specified value.
     *
     * <p>Corresponds to DIAMETER_ERROR_UNABLE_TO_COMPLY Result code IE as specified in 3GPP TS
     * 29.273
     */
    public static final int NOTIFY_ERROR_NETWORK_FAILURE = 10500;

    /** @hide */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({NOTIFY_ERROR_NO_APN_SUBSCRIPTION, NOTIFY_ERROR_NETWORK_FAILURE})
    public @interface BackoffCause {}

    private final byte mBackoffTimer;
    private final int mBackoffCause;

    public Ike3gppBackoffTimer(byte backoffTimer, int backoffCause) {
        mBackoffTimer = backoffTimer;
        mBackoffCause = backoffCause;
    }

    @Override
    public int getInfoType() {
        return INFO_TYPE_NOTIFY_BACKOFF_TIMER;
    }

    /** Returns the Backoff Timer specified by the peer. */
    public byte getBackoffTimer() {
        return mBackoffTimer;
    }

    /** Returns the cause for this Backoff Timer specified by the peer. */
    public int getBackoffCause() {
        return mBackoffCause;
    }
}
