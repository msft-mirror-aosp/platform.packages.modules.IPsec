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

package com.android.ike.eap.exceptions;

import com.android.ike.eap.message.EapSimAttribute.AtPadding;

/**
 * EapSimInvalidAtPaddingException is thrown when an {@link AtPadding} with invalid padding is
 * parsed. Per RFC 4186 Section 10.12, all padding bytes must be 0x00.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186#section-10.9">RFC 4186, EAP-SIM Authentication,
 * Section 10.12</a>
 */
public class EapSimInvalidAtPaddingException extends EapSimInvalidAttributeException {
    /**
     * Construct an instance of EapSimInvalidAtPaddingException with the specified detail message.
     *
     * @param message the detail message.
     */
    public EapSimInvalidAtPaddingException(String message) {
        super(message);
    }

    /**
     * Construct an instance of EapSimInvalidAtPaddingException with the specified message and
     * cause.
     *
     * @param message the detail message.
     * @param cause the cause.
     */
    public EapSimInvalidAtPaddingException(String message, Throwable cause) {
        super(message, cause);
    }
}
