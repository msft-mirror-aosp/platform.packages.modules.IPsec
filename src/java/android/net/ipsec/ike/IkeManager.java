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

import android.content.Context;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.net.utils.Log;

import java.util.concurrent.Executor;

/**
 * This class contains methods for managing IKE sessions.
 *
 * @hide
 */
public final class IkeManager {
    private static final String IKE_TAG = "IKE";
    private static final boolean LOG_SENSITIVE = false;

    private static Log sIkeLog = new Log(IKE_TAG, LOG_SENSITIVE);

    private final Context mContext;

    /**
     * Construct an instance of {@link IkeManager}
     *
     * @param context the application context.
     * @hide
     */
    public IkeManager(Context context) {
        mContext = context;
    }

    /**
     * Construct an instance of {@link IkeSession} and start the IKE Session setup process.
     *
     * <p>This method will immediately return a management object {@link IkeSession} and
     * asynchronously initiate the IKE Session setup process. Users will be notified of the IKE
     * Session and Child Session negotiation results on the callback arguments.
     *
     * @param ikeSessionOptions the {@link IkeSessionOptions} that contains acceptable IKE Session
     *     configurations.
     * @param firstChildSessionOptions the {@link ChildSessionOptions} that contains acceptable
     *     first Child Session configurations.
     * @param userCbExecutor the {@link Executor} upon which all callbacks will be posted. For
     *     security and consistency, the callbacks posted to this executor MUST be executed
     *     serially, in the order they were posted.
     * @param ikeSessionCallback the {@link IkeSessionCallback} interface to notify users the state
     *     changes of the IKE Session.
     * @param firstChildSessionCallback the {@link ChildSessionCallback} interface to notify users
     *     the state changes of the Child Session.
     * @return an instance of {@link IkeSession}
     * @hide
     */
    public IkeSession openIkeSession(
            IkeSessionOptions ikeSessionOptions,
            ChildSessionOptions firstChildSessionOptions,
            Executor userCbExecutor,
            IkeSessionCallback ikeSessionCallback,
            ChildSessionCallback firstChildSessionCallback) {
        return new IkeSession(
                mContext,
                ikeSessionOptions,
                firstChildSessionOptions,
                userCbExecutor,
                ikeSessionCallback,
                firstChildSessionCallback);
    }

    /**
     * Returns IKE logger.
     *
     * @hide
     */
    public static Log getIkeLog() {
        return sIkeLog;
    }

    /**
     * Injects IKE logger for testing.
     *
     * @hide
     */
    @VisibleForTesting
    public static void setIkeLog(Log log) {
        sIkeLog = log;
    }

    /**
     * Resets IKE logger.
     *
     * @hide
     */
    @VisibleForTesting
    public static void resetIkeLog() {
        sIkeLog = new Log(IKE_TAG, LOG_SENSITIVE);
    }
}
