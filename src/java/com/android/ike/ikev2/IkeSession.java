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
import android.net.IpSecManager;
import android.os.HandlerThread;

import com.android.internal.annotations.VisibleForTesting;

import dalvik.system.CloseGuard;

import java.util.concurrent.Executor;

/** This class represents an IKE Session management object. */
public final class IkeSession implements AutoCloseable {
    private final CloseGuard mCloseGuard = CloseGuard.get();

    @VisibleForTesting final IkeSessionStateMachine mIkeSessionStateMachine;

    /** Package private */
    IkeSession(
            Context context,
            IkeSessionOptions ikeSessionOptions,
            ChildSessionOptions firstChildSessionOptions,
            Executor userCbExecutor,
            IIkeSessionCallback ikeSessionCallback,
            IChildSessionCallback firstChildSessionCallback) {
        this(
                IkeThreadHolder.IKE_WORKER_THREAD,
                context,
                (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE),
                ikeSessionOptions,
                firstChildSessionOptions,
                userCbExecutor,
                ikeSessionCallback,
                firstChildSessionCallback);
    }

    /** Package private */
    @VisibleForTesting
    IkeSession(
            HandlerThread handlerThread,
            Context context,
            IpSecManager ipSecManager,
            IkeSessionOptions ikeSessionOptions,
            ChildSessionOptions firstChildSessionOptions,
            Executor userCbExecutor,
            IIkeSessionCallback ikeSessionCallback,
            IChildSessionCallback firstChildSessionCallback) {
        mIkeSessionStateMachine =
                new IkeSessionStateMachine(
                        handlerThread.getLooper(),
                        context,
                        ipSecManager,
                        ikeSessionOptions,
                        firstChildSessionOptions,
                        userCbExecutor,
                        ikeSessionCallback,
                        firstChildSessionCallback);

        mCloseGuard.open("open");
    }

    @Override
    public void finalize() {
        if (mCloseGuard != null) {
            mCloseGuard.warnIfOpen();
        }
    }

    /** Initialization-on-demand holder */
    private static class IkeThreadHolder {
        static final HandlerThread IKE_WORKER_THREAD;

        static {
            IKE_WORKER_THREAD = new HandlerThread("IkeWorkerThread");
            IKE_WORKER_THREAD.start();
        }
    }

    // TODO: b/133340675 Destroy the worker thread when there is no more alive {@link IkeSession}.

    /**
     * Initiate Create Child exchange on the IKE worker thread.
     *
     * <p>Users MUST provide a unique {@link IChildSessionCallback} instance for each new Child
     * Session.
     *
     * @param childSessionOptions the {@link ChildSessionOptions} that contains the Child Session
     *     configurations to negotiate.
     * @param childSessionCallback the {@link IChildSessionCallback} interface to notify users the
     *     state changes of the Child Session.
     * @throws IllegalArgumentException if the IChildSessionCallback is already in use.
     */
    public void openChildSession(
            ChildSessionOptions childSessionOptions, IChildSessionCallback childSessionCallback) {
        mIkeSessionStateMachine.openChildSession(childSessionOptions, childSessionCallback);
    }

    /**
     * Initiate Delete Child exchange on the IKE worker thread.
     *
     * @param childSessionCallback the callback of the Child Session to delete as well as the
     *     interface to notify users the deletion result.
     * @throws IllegalArgumentException if no Child Session found bound with this callback.
     */
    public void closeChildSession(IChildSessionCallback childSessionCallback) {
        mIkeSessionStateMachine.closeChildSession(childSessionCallback);
    }

    /**
     * Initiate Delete IKE exchange on the IKE worker thread.
     *
     * <p>Users must stop all outbound traffic that uses the Child Sessions that under this IKE
     * Session before calling this method.
     */
    public void closeSafely() {
        mCloseGuard.close();
        mIkeSessionStateMachine.closeSession();
    }

    /**
     * Notify the remote server and close the IKE Session.
     *
     * <p>Implement {@link AutoCloseable#close()}
     *
     * <p>Users must stop all outbound traffic that uses the Child Sessions that under this IKE
     * Session before calling this method.
     */
    @Override
    public void close() throws Exception {
        mCloseGuard.close();
        mIkeSessionStateMachine.closeSession();
    }

    // TODO: Add methods to retrieve negotiable and non-negotiable configurations of IKE Session and
    // its Child Sessions.
}
