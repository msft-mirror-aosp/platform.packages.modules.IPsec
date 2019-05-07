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

package com.android.ike.ikev2.message;

import android.util.Pair;

import com.android.ike.TestUtils;
import com.android.ike.ikev2.exceptions.IkeProtocolException;

import java.nio.ByteBuffer;

/** IkeTestUtils provides utility methods for parsing Hex String */
public final class IkeTestUtils {
    public static IkePayload hexStringToIkePayload(
            @IkePayload.PayloadType int payloadType, boolean isResp, String payloadHexString)
            throws IkeProtocolException {
        byte[] payloadBytes = TestUtils.hexStringToByteArray(payloadHexString);
        // Returned Pair consists of the IkePayload and the following IkePayload's type.
        Pair<IkePayload, Integer> pair =
                IkePayloadFactory.getIkePayload(payloadType, isResp, ByteBuffer.wrap(payloadBytes));
        return pair.first;
    }
}
