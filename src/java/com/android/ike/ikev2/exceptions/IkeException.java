/*
 * Copyright (C) 2018 The Android Open Source Project
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
 * IkeException is an abstract class that represents the common information for all IKE protocol
 * errors.
 *
 * <p>Each types of IKE error should implement its own subclass
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.10.1">, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public abstract class IkeException extends Exception {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_MAJOR_VERSION, INVALID_SYNTAX})
    public @interface ErrorType {}
    /** Unsupported critical payload */
    public static final int UNSUPPORTED_CRITICAL_PAYLOAD = 1;
    /** Major version is larger than 2 */
    public static final int INVALID_MAJOR_VERSION = 5;
    /** There is field that out of range */
    public static final int INVALID_SYNTAX = 7;

    @ErrorType public final int errorCode;

    /**
     * Construct an instance of IkeException
     *
     * @param code the protocol error code
     */
    public IkeException(@ErrorType int code) {
        super();
        errorCode = code;
    }
}
