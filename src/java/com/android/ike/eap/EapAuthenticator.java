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

package com.android.ike.eap;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.statemachine.EapStateMachine;
import com.android.internal.annotations.VisibleForTesting;

import java.security.SecureRandom;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

/**
 * EapAuthenticator represents an EAP peer implementation.
 *
 * @see <a href="https://tools.ietf.org/html/rfc3748#section-4">RFC 3748, Extensible Authentication
 * Protocol (EAP)</a>
 */
public class EapAuthenticator extends Handler {
    private static final String TAG = EapAuthenticator.class.getSimpleName();
    private static final long DEFAULT_TIMEOUT_MILLIS = 7000L;

    private final Executor mWorkerPool;
    private final EapStateMachine mStateMachine;
    private final IEapCallback mCb;
    private final Handler mCbHandler;
    private final long mTimeoutMillis;
    private boolean mCallbackFired = false;

    /**
     * Constructor for EapAuthenticator
     *
     * @param looper Looper for running a message loop
     * @param cbHandler Handler for posting callbacks to the given IEapCallback
     * @param cb IEapCallback for callbacks to the client
     * @param context Context for this EapAuthenticator
     */
    public EapAuthenticator(Looper looper, Handler cbHandler, IEapCallback cb, Context context) {
        this(looper,
                cbHandler,
                cb,
                new EapStateMachine(context, new SecureRandom()),
                Executors.newSingleThreadExecutor(),
                DEFAULT_TIMEOUT_MILLIS);
    }

    @VisibleForTesting
    EapAuthenticator(
            Looper looper,
            Handler cbHandler,
            IEapCallback cb,
            EapStateMachine eapStateMachine,
            Executor executor,
            long timeoutMillis) {
        super(looper);

        mCbHandler = cbHandler;
        mCb = cb;
        mStateMachine = eapStateMachine;
        mWorkerPool = executor;
        mTimeoutMillis = timeoutMillis;
    }

    @Override
    public void handleMessage(Message msg) {
        // No messages processed here. Only runnables. Drop all messages.
    }

    /**
     * Processes the given msgBytes within the context of the current EAP Session.
     *
     * <p>If the given message is successfully processed, the relevant {@link IEapCallback} function
     * is used. Otherwise, {@link IEapCallback#onError(Throwable)} is called.
     *
     * @param msgBytes the byte-array encoded EAP message to be processed
     */
    public void processEapMessage(byte[] msgBytes) {
        // reset
        mCallbackFired = false;

        mCbHandler.postDelayed(() -> {
            if (!mCallbackFired) {
                // Fire failed callback
                mCallbackFired = true;
                mCb.onError(new TimeoutException("Timeout while processing message"));
            }
        }, EapAuthenticator.this, mTimeoutMillis);

        // proxy to worker thread for async processing
        mWorkerPool.execute(() -> {
            // Any unhandled exceptions within the state machine are caught here to make sure that
            // the caller does not wait for the full timeout duration before being notified of a
            // failure.
            EapResult processResponse;
            try {
                processResponse = mStateMachine.process(msgBytes);
            } catch (Exception ex) {
                Log.e(TAG, "Exception thrown while processing message", ex);
                processResponse = new EapError(ex);
            }

            final EapResult finalProcessResponse = processResponse;
            mCbHandler.post(() -> {
                // No synchronization needed, since Handler serializes
                if (!mCallbackFired) {
                    if (finalProcessResponse instanceof EapResponse) {
                        mCb.onResponse(((EapResponse) finalProcessResponse).packet);
                    } else if (finalProcessResponse instanceof EapError) {
                        mCb.onError(((EapError) finalProcessResponse).cause);
                    } else if (finalProcessResponse instanceof EapSuccess) {
                        EapSuccess eapSuccess = (EapSuccess) finalProcessResponse;
                        mCb.onSuccess(eapSuccess.msk, eapSuccess.emsk);
                    } else { // finalProcessResponse instanceof EapFailure
                        mCb.onFail();
                    }

                    mCallbackFired = true;

                    // Ensure delayed timeout runnable does not fire
                    mCbHandler.removeCallbacksAndMessages(EapAuthenticator.this);
                }
            });
        });
    }
}
