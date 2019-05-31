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

import com.android.ike.ikev2.exceptions.IkeException;

/** Callback interface for receiving state changes of an IKE Session. */
public interface IIkeSessionCallback {
    /** Called when negotiation and authentication for this new IKE Session succeeds. */
    void onOpened();

    /**
     * Called when either side has decided to close this Session and the deletion exchange
     * finishes.
     *
     * <p>This method will not be fired if this deletion is caused by a fatal error.
     */
    void onClosed();

    /**
     * Called if IKE Session negotiation fails or IKE Session is deleted because of a fatal error.
     *
     * @param exception the detailed error.
     */
    void onError(IkeException exception);

    /**
     * Called if a recoverable error is encountered in an established IKE Session.
     *
     * <p>A potential risk is usually detected when IKE library receives a non-protected error
     * notification (e.g. INVALID_IKE_SPI) or a non-fatal error notification (e.g.
     * INVALID_MESSAGE_ID).
     *
     * @param exception the detailed error.
     */
    void onInfo(IkeException exception);
}
