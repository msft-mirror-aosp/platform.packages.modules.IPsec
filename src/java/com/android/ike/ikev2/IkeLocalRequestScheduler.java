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

import java.util.LinkedList;

/**
 * IkeLocalRequestScheduler caches all local requests scheduled by an IKE Session and notify the IKE
 * Session to process the request when it is allowed.
 *
 * <p>LocalRequestScheduler is running on the IkeSessionStateMachine thread.
 */
public final class IkeLocalRequestScheduler {
    private final LinkedList<LocalRequest> mRequestQueue = new LinkedList<>();

    private final IProcedureConsumer mConsumer;

    private boolean mLocalProcedureOngoing;
    private boolean mRemoteProcedureOngoing;

    /**
     * Construct an instance of IkeLocalRequestScheduler
     *
     * @param consumer the interface to initiate new procedure.
     */
    public IkeLocalRequestScheduler(IProcedureConsumer consumer) {
        mConsumer = consumer;
    }

    /** Add a new local request to the queue. */
    public void addRequest(LocalRequest request) {
        mRequestQueue.offer(request);
    }

    /** Add a new local request to the front of the queue. */
    public void addRequestAtFront(LocalRequest request) {
        mRequestQueue.offerFirst(request);
    }

    /**
     * Notifies the scheduler that the caller is ready for a new procedure
     *
     * <p>Synchronously triggers the call to onNewProcedureReady.
     */
    public void readyForNextProcedure() {
        if (!mRequestQueue.isEmpty()) {
            LocalRequest request = mRequestQueue.poll();
            mConsumer.onNewProcedureReady(request);
            return;
        }
    }

    /**
     * This class represents a user requested or internally scheduled IKE procedure that will be
     * initiated locally.
     */
    public static class LocalRequest {
        public final int procedureType;
        // TODO: Also store specific payloads for INFO exchange.
        // TODO: Support cancelling a scheduled rekey request

        LocalRequest(int type) {
            procedureType = type;
        }
    }

    /**
     * This class represents a user requested or internally scheduled Child procedure that will be
     * initiated locally.
     */
    public static class ChildLocalRequest extends LocalRequest {
        public final IChildSessionCallback childSessionCallback;
        public final ChildSessionOptions childSessionOptions;

        ChildLocalRequest(
                int type, IChildSessionCallback childCallback, ChildSessionOptions childOptions) {
            super(type);
            childSessionOptions = childOptions;
            childSessionCallback = childCallback;
        }
    }

    /** Interface to initiate a new IKE procedure */
    public interface IProcedureConsumer {
        /**
         * Called when a new IKE procedure can be initiated.
         *
         * @param localRequest the request to be initiated.
         */
        void onNewProcedureReady(LocalRequest localRequest);
    }
}
