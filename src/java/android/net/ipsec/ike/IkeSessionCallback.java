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
import android.net.ipsec.ike.exceptions.IkeException;
import android.net.ipsec.ike.exceptions.IkeProtocolException;

/**
 * Callback interface for receiving state changes of an IKE Session.
 *
 * @hide
 */
public interface IkeSessionCallback {
    /**
     * Called when negotiation and authentication for this new IKE Session succeeds.
     *
     * @param sessionConfiguration the configuration information of IKE Session negotiated during
     *     IKE setup.
     * @hide
     */
    void onOpened(@NonNull IkeSessionConfiguration sessionConfiguration);

    /**
     * Called when either side has decided to close this Session and the deletion exchange finishes.
     *
     * <p>This method will not be fired if this deletion is caused by a fatal error.
     *
     * @hide
     */
    void onClosed();

    /**
     * Called if IKE Session negotiation fails or IKE Session is closed because of a fatal error.
     *
     * @param exception the detailed error.
     * @hide
     */
    void onClosedExceptionally(IkeException exception);

    /**
     * Called if a recoverable error is encountered in an established {@link IkeSession}.
     *
     * <p>This method may be triggered by protocol errors such as an INVALID_IKE_SPI or
     * INVALID_MESSAGE_ID.
     *
     * @param exception the detailed error information.
     * @hide
     */
    void onError(IkeProtocolException exception);
}
