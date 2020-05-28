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
package com.android.internal.net.ipsec.ike;

import static com.android.internal.net.ipsec.ike.AbstractSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_CHILD;
import static com.android.internal.net.ipsec.ike.AbstractSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_CHILD;
import static com.android.internal.net.ipsec.ike.IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE;
import static com.android.internal.net.ipsec.ike.IkeSessionStateMachine.CMD_LOCAL_REQUEST_DPD;

import android.net.ipsec.ike.ChildSessionCallback;
import android.net.ipsec.ike.ChildSessionParams;

import java.util.LinkedList;

/**
 * IkeLocalRequestScheduler caches all local requests scheduled by an IKE Session and notify the IKE
 * Session to process the request when it is allowed.
 *
 * <p>LocalRequestScheduler is running on the IkeSessionStateMachine thread.
 */
public final class IkeLocalRequestScheduler {
    public static int SPI_NOT_INCLUDED = 0;

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
     *
     * @return whether or not a new procedure was scheduled.
     */
    public boolean readyForNextProcedure() {
        if (!mRequestQueue.isEmpty()) {
            mConsumer.onNewProcedureReady(mRequestQueue.poll());
            return true;
        }
        return false;
    }

    /**
     * This class represents the common information of procedures that will be locally initiated.
     */
    public abstract static class LocalRequest {
        public final int procedureType;

        LocalRequest(int type) {
            validateTypeOrThrow(type);
            procedureType = type;
        }

        protected abstract void validateTypeOrThrow(int type);

        protected abstract boolean isChildRequest();
    }

    /**
     * This class represents a user requested or internally scheduled IKE procedure that will be
     * initiated locally.
     */
    public static class IkeLocalRequest extends LocalRequest {
        public long remoteSpi;

        /** Schedule a request for the IKE Session */
        IkeLocalRequest(int type) {
            this(type, SPI_NOT_INCLUDED);
        }

        /** Schedule a request for an IKE SA that is identified by the remoteIkeSpi */
        IkeLocalRequest(int type, long remoteIkeSpi) {
            super(type);
            remoteSpi = remoteIkeSpi;
        }

        @Override
        protected void validateTypeOrThrow(int type) {
            if (type >= CMD_LOCAL_REQUEST_CREATE_IKE && type <= CMD_LOCAL_REQUEST_DPD) return;
            throw new IllegalArgumentException("Invalid IKE procedure type: " + type);
        }

        @Override
        protected boolean isChildRequest() {
            return false;
        }
    }

    /**
     * This class represents a user requested or internally scheduled Child procedure that will be
     * initiated locally.
     */
    public static class ChildLocalRequest extends LocalRequest {
        public int remoteSpi;
        public final ChildSessionCallback childSessionCallback;
        public final ChildSessionParams childSessionParams;

        /** Schedule a request for a Child Session that is identified by the childCallback */
        ChildLocalRequest(
                int type, ChildSessionCallback childCallback, ChildSessionParams childParams) {
            this(type, SPI_NOT_INCLUDED, childCallback, childParams);
        }

        /** Schedule a request for a Child SA that is identified by the remoteChildSpi */
        ChildLocalRequest(int type, int remoteChildSpi) {
            this(type, remoteChildSpi, null /*childCallback*/, null /*childParams*/);
        }

        private ChildLocalRequest(
                int type,
                int remoteChildSpi,
                ChildSessionCallback childCallback,
                ChildSessionParams childParams) {
            super(type);
            childSessionParams = childParams;
            childSessionCallback = childCallback;
            remoteSpi = remoteChildSpi;
        }

        @Override
        protected void validateTypeOrThrow(int type) {
            if (type >= CMD_LOCAL_REQUEST_CREATE_CHILD && type <= CMD_LOCAL_REQUEST_REKEY_CHILD) {
                return;
            }

            throw new IllegalArgumentException("Invalid Child procedure type: " + type);
        }

        @Override
        protected boolean isChildRequest() {
            return true;
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
