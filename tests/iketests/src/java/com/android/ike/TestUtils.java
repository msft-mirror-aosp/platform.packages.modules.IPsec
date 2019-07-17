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

package com.android.ike;

import java.nio.ByteBuffer;

/** TestUtils provides utility methods for parsing Hex String */
public class TestUtils {
    public static byte[] hexStringToByteArray(String hexString) {
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

    public static int hexStringToInt(String hexString) {
        if (hexString.length() > 8) {
            throw new IllegalArgumentException("Invalid hex string length for integer type");
        }

        for (int i = hexString.length(); i < 8; i++) {
            hexString = "0" + hexString;
        }

        return ByteBuffer.wrap(hexStringToByteArray(hexString)).getInt();
    }

    public static String stringToHexString(String s) {
        // two hex characters for each char in s
        StringBuilder sb = new StringBuilder(s.length() * 2);
        char[] chars = s.toCharArray();
        for (char c : chars) {
            sb.append(Integer.toHexString(c));
        }
        return sb.toString();
    }
}
