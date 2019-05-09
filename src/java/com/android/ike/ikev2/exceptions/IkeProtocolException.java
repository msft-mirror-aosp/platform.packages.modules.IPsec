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
package com.android.ike.ikev2.exceptions;

import android.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * IkeProtocolException is an abstract class that represents the common information for all IKE
 * protocol errors.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.10.1">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public abstract class IkeProtocolException extends IkeException {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD,
        ERROR_TYPE_INVALID_IKE_SPI,
        ERROR_TYPE_INVALID_MAJOR_VERSION,
        ERROR_TYPE_INVALID_SYNTAX,
        ERROR_TYPE_INVALID_MESSAGE_ID,
        ERROR_TYPE_NO_PROPOSAL_CHOSEN,
        ERROR_TYPE_INVALID_KE_PAYLOAD,
        ERROR_TYPE_AUTHENTICATION_FAILED,
        ERROR_TYPE_SINGLE_PAIR_REQUIRED,
        ERROR_TYPE_NO_ADDITIONAL_SAS,
        ERROR_TYPE_INTERNAL_ADDRESS_FAILURE,
        ERROR_TYPE_FAILED_CP_REQUIRED,
        ERROR_TYPE_TS_UNACCEPTABLE,
        ERROR_TYPE_INVALID_SELECTORS,
        ERROR_TYPE_TEMPORARY_FAILURE,
        ERROR_TYPE_CHILD_SA_NOT_FOUND,
    })
    public @interface ErrorType {}

    public static final int ERROR_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD = 1;
    public static final int ERROR_TYPE_INVALID_IKE_SPI = 4;
    public static final int ERROR_TYPE_INVALID_MAJOR_VERSION = 5;
    public static final int ERROR_TYPE_INVALID_SYNTAX = 7;
    public static final int ERROR_TYPE_INVALID_MESSAGE_ID = 9;
    public static final int ERROR_TYPE_NO_PROPOSAL_CHOSEN = 14;
    public static final int ERROR_TYPE_INVALID_KE_PAYLOAD = 17;
    public static final int ERROR_TYPE_AUTHENTICATION_FAILED = 24;
    public static final int ERROR_TYPE_SINGLE_PAIR_REQUIRED = 34;
    public static final int ERROR_TYPE_NO_ADDITIONAL_SAS = 35;
    public static final int ERROR_TYPE_INTERNAL_ADDRESS_FAILURE = 36;
    public static final int ERROR_TYPE_FAILED_CP_REQUIRED = 37;
    public static final int ERROR_TYPE_TS_UNACCEPTABLE = 38;
    public static final int ERROR_TYPE_INVALID_SELECTORS = 39;
    public static final int ERROR_TYPE_TEMPORARY_FAILURE = 43;
    public static final int ERROR_TYPE_CHILD_SA_NOT_FOUND = 44;

    public static final int ERROR_DATA_NOT_INCLUDED = Integer.MIN_VALUE;

    @ErrorType private final int mErrorType;
    private final boolean mHasErrorData;
    private final int mErrorData;

    // TODO: Add a flag to indicate if this error is in an inbound message.

    protected IkeProtocolException(@ErrorType int code) {
        super();
        mErrorType = code;
        mHasErrorData = false;
        mErrorData = ERROR_DATA_NOT_INCLUDED;
    }

    protected IkeProtocolException(@ErrorType int code, int errorData) {
        super();
        mErrorType = code;
        mHasErrorData = true;
        mErrorData = errorData;
    }

    protected IkeProtocolException(@ErrorType int code, String message) {
        super(message);
        mErrorType = code;
        mHasErrorData = false;
        mErrorData = ERROR_DATA_NOT_INCLUDED;
    }

    protected IkeProtocolException(@ErrorType int code, Throwable cause) {
        super(cause);
        mErrorType = code;
        mHasErrorData = false;
        mErrorData = ERROR_DATA_NOT_INCLUDED;
    }

    /**
     * Returns the IKE standard protocol error type of this {@link IkeProtocolException} instance.
     *
     * @return the IKE standard protocol error type.
     */
    @ErrorType
    public int getErrorType() {
        return mErrorType;
    }

    /**
     * Returns if an error data is included in this {@link IkeProtocolException} instance.
     *
     * @return true if an error data is included in this {@link IkeProtocolException} instance,
     *     false otherwise.
     */
    public boolean hasErrorData() {
        return mHasErrorData;
    }

    /**
     * Returns the included error data of this {@link IkeProtocolException} instance.
     *
     * <p>Note that only few error types will go with an error data. This data has different meaning
     * with different error types. Users should first check if an error data is included before they
     * call this method.
     *
     * @return the included error data.
     */
    public int getErrorData() {
        return mErrorData;
    }
}
