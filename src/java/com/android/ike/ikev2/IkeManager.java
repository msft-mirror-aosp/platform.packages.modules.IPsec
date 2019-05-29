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

import android.content.Context;

import java.util.concurrent.Executor;

/** This class contains methods for managing IKE sessions. */
public final class IkeManager {
    /**
     * Construct an instance of {@link IkeSession} and start the IKE Session setup process.
     *
     * <p>This method will immediately return a management object {@link IkeSession} and
     * asynchronously initiate the IKE Session setup process. Users will be notified of the IKE
     * Session and Child Session negotiation results on the callback arguments.
     *
     * @param context the application context for IKE and Child Sessions.
     * @param ikeSessionOptions the {@link IkeSessionOptions} that contains acceptable IKE Session
     *     configurations.
     * @param firstChildSessionOptions the {@link ChildSessionOptions} that contains acceptable
     *     first Child Session configurations.
     * @param callbackExecutor the {@link Executor} upon which all callbacks will be executed. This
     *     method will enforce that these are executed sequentially.
     * @param ikeSessionCallback the {@link IIkeSessionCallback} interface to notify users the state
     *     changes of the IKE Session.
     * @param firstChildSessionCallback the {@link IChildSessionCallback} interface to notify users
     *     the state changes of the Child Session.
     * @return an instance of {@link IkeSession}
     */
    public static IkeSession openIkeSession(
            Context context,
            IkeSessionOptions ikeSessionOptions,
            ChildSessionOptions firstChildSessionOptions,
            Executor callbackExecutor,
            IIkeSessionCallback ikeSessionCallback,
            IChildSessionCallback firstChildSessionCallback) {
        return new IkeSession(
                context,
                ikeSessionOptions,
                firstChildSessionOptions,
                callbackExecutor,
                ikeSessionCallback,
                firstChildSessionCallback);
    }
}
