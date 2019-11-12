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

import android.net.IpSecManager.PolicyDirection;
import android.net.IpSecTransform;
import android.net.ipsec.ike.exceptions.IkeException;

/**
 * Callback interface for receiving state changes of a Child Session.
 *
 * @hide
 */
public interface ChildSessionCallback {
    /**
     * Called when Child Session setup succeeds.
     *
     * @param sessionConfiguration the configuration information of Child Session negotiated during
     *     Child creation.
     * @hide
     */
    void onOpened(ChildSessionConfiguration sessionConfiguration);

    /**
     * Called when either side has decided to close this Session and the deletion exchange finishes.
     *
     * <p>This method will not be fired if this deletion is caused by a fatal error.
     *
     * @hide
     */
    void onClosed();

    /**
     * Called if Child Session setup fails or Child Session is closed because of a fatal error.
     *
     * @param exception the detailed error.
     * @hide
     */
    void onClosedExceptionally(IkeException exception);

    /**
     * Called when a new {@link IpSecTransform} is created for this Child Session.
     *
     * @param ipSecTransform the created {@link IpSecTransform}
     * @param direction the direction of this {@link IpSecTransform}
     * @hide
     */
    void onIpSecTransformCreated(IpSecTransform ipSecTransform, @PolicyDirection int direction);

    /**
     * Called when a new {@link IpSecTransform} is deleted for this Child Session.
     *
     * <p>Users MUST remove the transform from the socket or interface. Otherwise the communication
     * on that socket or interface will fail.
     *
     * @param ipSecTransform the deleted {@link IpSecTransform}
     * @param direction the direction of this {@link IpSecTransform}
     * @hide
     */
    void onIpSecTransformDeleted(IpSecTransform ipSecTransform, @PolicyDirection int direction);
}
