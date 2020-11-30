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
import android.net.IpSecTransform;
import android.net.annotations.PolicyDirection;
import android.net.ipsec.ike.exceptions.IkeException;

/**
 * Callback interface for receiving state changes of a Child Session.
 *
 * <p>{@link ChildSessionCallback} MUST be unique to each Child Session. It is registered when
 * callers are requesting a new Child Session. It is automatically unregistered when a Child Session
 * or the parent IKE Session is closed.
 *
 * <p>{@link ChildSessionCallback}s are also used for identifying Child Sessions. It is required
 * when a caller wants to delete a specific Child Session.
 */
// Using interface instead of abstract class to indicate this callback does not have any state or
// implementation.
@SuppressLint("CallbackInterface")
public interface ChildSessionCallback {
    /**
     * Called when the Child Session setup succeeds.
     *
     * <p>This method will be called immediately after {@link
     * #onIpSecTransformCreated(IpSecTransform, int)} for the created IPsec SA pair is fired.
     *
     * @param sessionConfiguration the {@link ChildSessionConfiguration} of Child Session negotiated
     *     during Child creation.
     */
    void onOpened(@NonNull ChildSessionConfiguration sessionConfiguration);

    /**
     * Called when the Child Session is closed.
     *
     * <p>This method will be called immediately after {@link
     * #onIpSecTransformDeleted(IpSecTransform, int)} for the deleted IPsec SA pair is fired.
     *
     * <p>When the closure is caused by a local, fatal error, {@link
     * #onClosedExceptionally(IkeException)} will be fired instead of this method.
     */
    void onClosed();

    /**
     * Called if the Child Session setup failed or Child Session is closed because of a fatal error.
     *
     * <p>This method will be called immediately after {@link
     * #onIpSecTransformDeleted(IpSecTransform, int)} for the deleted IPsec SA pair is fired.
     *
     * @param exception the detailed error information.
     */
    void onClosedExceptionally(@NonNull IkeException exception);

    /**
     * Called when an {@link IpSecTransform} is created by this Child Session.
     *
     * <p>This method is fired when a Child Session is created or rekeyed.
     *
     * <p>The {@link IpSecTransform} must be applied to relevant sockets or interfaces when this
     * method is called; traffic may otherwise flow over the socket or interface unprotected.
     *
     * <p>As this method is fired on an executor, there is an inherent race condition during rekeys
     * where traffic may be routed through the old transforms while the remote has switched to using
     * the new set of transforms.
     *
     * <p>To avoid the initial startup race condition where the transforms have not yet been
     * applied, the {@link onOpened(ChildSessionConfiguration)} callback should be used as the
     * authoritative signal that the socket or tunnel is ready, as it is fired after both transforms
     * have had a chance to be applied.
     *
     * @param ipSecTransform the created {@link IpSecTransform}.
     * @param direction the direction of this {@link IpSecTransform}.
     */
    void onIpSecTransformCreated(
            @NonNull IpSecTransform ipSecTransform, @PolicyDirection int direction);

    /**
     * Called when an {@link IpSecTransform} is deleted by this Child Session.
     *
     * <p>This method is fired when a Child Session is closed or a Child Session has deleted old
     * IPsec SA during rekey. When this method is fired due to Child Session closure, it will be
     * followed by {@link #onClosed()} or {@link #onClosedExceptionally(IkeException)}.
     *
     * <p>Users SHOULD remove the {@link IpSecTransform} from the socket or interface when this
     * method is called. Otherwise the IPsec traffic protected by this {@link IpSecTransform} will
     * be discarded.
     *
     * @param ipSecTransform the deleted {@link IpSecTransform}.
     * @param direction the direction of this {@link IpSecTransform}.
     */
    void onIpSecTransformDeleted(
            @NonNull IpSecTransform ipSecTransform, @PolicyDirection int direction);
}
