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
import android.annotation.SuppressLint;
import android.annotation.SystemApi;
import android.net.ipsec.ike.exceptions.IkeException;
import android.net.ipsec.ike.exceptions.IkeProtocolException;

/**
 * Callback interface for receiving state changes of an {@link IkeSession}.
 *
 * <p>{@link IkeSessionCallback} MUST be unique to each {@link IkeSession}. It is registered when
 * callers are requesting a new {@link IkeSession}. It is automatically unregistered when an {@link
 * IkeSession} is closed.
 */
// Using interface instead of abstract class to indicate this callback does not have any state or
// implementation.
@SuppressLint("CallbackInterface")
public interface IkeSessionCallback {
    /**
     * Called when the {@link IkeSession} setup succeeds.
     *
     * <p>This method does not indicate the first Child Session has been setup. Caller MUST refer to
     * the corresponding {@link ChildSessionCallback} for the Child Session setup result.
     *
     * @param sessionConfiguration the configuration information of {@link IkeSession} negotiated
     *     during IKE setup.
     */
    void onOpened(@NonNull IkeSessionConfiguration sessionConfiguration);

    /**
     * Called when the {@link IkeSession} is closed.
     *
     * <p>When the closure is caused by a local, fatal error, {@link
     * #onClosedExceptionally(IkeException)} will be fired instead of this method.
     */
    void onClosed();

    /**
     * Called if {@link IkeSession} setup failed or {@link IkeSession} is closed because of a fatal
     * error.
     *
     * @param exception the detailed error information.
     */
    void onClosedExceptionally(@NonNull IkeException exception);

    /**
     * Called if a recoverable error is encountered in an established {@link IkeSession}.
     *
     * <p>This method may be triggered by protocol errors such as an INVALID_IKE_SPI or
     * INVALID_MESSAGE_ID.
     *
     * @param exception the detailed error information.
     * @hide
     */
    // TODO: b/158033037 Deprecate this method and add a public API that takes an IkeException when
    // exposing MOBIKE APIs
    @SystemApi
    void onError(@NonNull IkeProtocolException exception);

    /**
     * Called if a recoverable error is encountered in an established {@link IkeSession}.
     *
     * <p>This method may be triggered by protocol errors such as an INVALID_IKE_SPI, or by
     * non-protocol errors such as the underlying {@link android.net.Network} dying.
     *
     * @param exception the detailed error information.
     * @hide
     */
    default void onError(@NonNull IkeException exception) {
        if (exception instanceof IkeProtocolException) {
            onError((IkeProtocolException) exception);
            return;
        }

        // do nothing for non-protocol errors by default
    }

    /**
     * Called if the IkeSessionConnectionInfo for an established {@link IkeSession} changes.
     *
     * <p>This method will only be called for MOBIKE-enabled Sessions, and only after a Mobility
     * Event occurs.
     *
     * <p>A Mobility Event is an event that causes the established, MOBIKE-enabled IKE Session to
     * undergo an address update. Specifically, these events are:
     *
     * <ul>
     *   <li>The underlying Network changing, or
     *   <li>The local address disappearing from the current underlying (and unchanged) Network, or
     *   <li>The remote address changing.
     * </ul>
     *
     * @param connectionInfo the updated IkeSessionConnectionInfo for the Session.
     * @hide
     */
    void onIkeSessionConnectionInfoChanged(@NonNull IkeSessionConnectionInfo connectionInfo);
}
