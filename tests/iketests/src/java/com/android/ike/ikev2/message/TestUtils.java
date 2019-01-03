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

package com.android.ike.ikev2.message;

/** TestUtils provides utility methods for parsing Hex String */
public final class TestUtils {
    /**
     * Converts the unsigned Hex String to a byte array.
     *
     * @param hexString hex representation of an unsigned value.
     * @return the converted byte array.
     * @throws IllegalArgumentException when length of Hex String is an odd number.
     */
    public static byte[] hexStringToByteArray(String hexString) throws IllegalArgumentException {
        int len = hexString.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Invalid Hex String");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(hexString.charAt(i), 16) << 4)
                                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
