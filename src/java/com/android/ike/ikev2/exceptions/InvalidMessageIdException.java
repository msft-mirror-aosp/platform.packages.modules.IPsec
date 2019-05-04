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

/**
 * This exception is thrown when the message ID is out of window size.
 *
 * <p>Notifications based on this exception MUST only ever be sent in an INFORMATIONAL request.
 * Sending this notification is OPTIONAL, and notifications of this type MUST be rate limited.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-2.3">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public final class InvalidMessageIdException extends IkeProtocolException {
    public final int invalidMessageId;

    /**
     * Construct a instance of InvalidMessageIdException
     *
     * @param messageId the invalid Message ID.
     */
    public InvalidMessageIdException(int messageId) {
        super(ERROR_TYPE_INVALID_MESSAGE_ID);
        invalidMessageId = messageId;
    }
}
