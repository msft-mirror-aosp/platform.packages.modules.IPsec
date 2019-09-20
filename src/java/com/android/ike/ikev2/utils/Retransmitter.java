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
package com.android.ike.ikev2.utils;

import static com.android.ike.ikev2.IkeSessionStateMachine.CMD_RETRANSMIT;

import android.os.Handler;

import com.android.ike.ikev2.message.IkeMessage;
import com.android.internal.annotations.VisibleForTesting;

/**
 * Retransmitter represents a class that will send a message and trigger delayed retransmissions
 *
 * <p>The Retransmitter class will queue retransmission signals on the provided handler. The owner
 * of this retransmitter instance is expected to wait for the signal, and call retransmit() on the
 * instance of this class.
 */
public abstract class Retransmitter {
    private static IBackoffTimeoutCalculator sBackoffTimeoutCalculator =
            new BackoffTimeoutCalculator();

    /*
     * Retransmit parameters
     *
     * (Re)transmission count   | Relative timeout  | Absolute timeout
     * -------------------------+-------------------+------------------
     * 0                        | 500ms             | 500ms
     * 1                        | 1s                | 1.5s
     * 2                        | 2s                | 3.5s
     * 3                        | 4s                | 7.5s
     * 4                        | 8s                | 15.5s
     * 5                        | 16s               | 31.5s
     *
     * TODO: Add retransmitter configurability
     */
    static final double RETRANSMIT_BACKOFF_FACTOR = 2.0;
    static final long RETRANSMIT_TIMEOUT_MS = 500L;
    static final int RETRANSMIT_MAX_ATTEMPTS = 5;

    private final Handler mHandler;
    private final IkeMessage mRetransmitMsg;
    private int mRetransmitCount = 0;

    public Retransmitter(Handler handler, IkeMessage msg) {
        mHandler = handler;
        mRetransmitMsg = msg;
    }

    /**
     * Triggers a (re)transmission. Will enqueue a future retransmission signal on the given handler
     */
    public void retransmit() {
        if (mRetransmitMsg == null) {
            return;
        }

        // If the failed iteration is beyond the max attempts, clean up and shut down.
        if (mRetransmitCount > RETRANSMIT_MAX_ATTEMPTS) {
            handleRetransmissionFailure();
            return;
        }

        send(mRetransmitMsg);

        long timeout = sBackoffTimeoutCalculator.getExponentialBackoffTimeout(mRetransmitCount++);
        mHandler.sendMessageDelayed(mHandler.obtainMessage(CMD_RETRANSMIT, this), timeout);
    }

    /** Cancels any future retransmissions */
    public void stopRetransmitting() {
        mHandler.removeMessages(CMD_RETRANSMIT, this);
    }

    /** Retrieves the message this retransmitter is tracking */
    public IkeMessage getMessage() {
        return mRetransmitMsg;
    }

    /**
     * Implementation-provided sender
     *
     * <p>For Retransmitter-internal use only.
     *
     * @param msg the message to be sent
     */
    protected abstract void send(IkeMessage msg);

    /**
     * Callback for implementations to be informed that we have reached the max retransmissions.
     *
     * <p>For Retransmitter-internal use only.
     */
    protected abstract void handleRetransmissionFailure();

    /**
     * IBackoffTimeoutCalculator provides interface for calculating retransmission backoff timeout.
     *
     * <p>IBackoffTimeoutCalculator exists so that the interface is injectable for testing.
     */
    @VisibleForTesting
    public interface IBackoffTimeoutCalculator {
        /** Calculate retransmission backoff timeout */
        long getExponentialBackoffTimeout(int retransmitCount);
    }

    private static final class BackoffTimeoutCalculator implements IBackoffTimeoutCalculator {
        @Override
        public long getExponentialBackoffTimeout(int retransmitCount) {
            double expBackoffFactor = Math.pow(RETRANSMIT_BACKOFF_FACTOR, retransmitCount);
            return (long) (RETRANSMIT_TIMEOUT_MS * expBackoffFactor);
        }
    }

    /** Sets IBackoffTimeoutCalculator */
    @VisibleForTesting
    public static void setBackoffTimeoutCalculator(IBackoffTimeoutCalculator calculator) {
        sBackoffTimeoutCalculator = calculator;
    }

    /** Resets BackoffTimeoutCalculator of retransmitter */
    @VisibleForTesting
    public static void resetBackoffTimeoutCalculator() {
        sBackoffTimeoutCalculator = new BackoffTimeoutCalculator();
    }
}
