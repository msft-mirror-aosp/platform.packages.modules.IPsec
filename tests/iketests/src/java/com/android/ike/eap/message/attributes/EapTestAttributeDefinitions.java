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

package com.android.ike.eap.message.attributes;

import static com.android.ike.TestUtils.hexStringToByteArray;

/**
 * EapTestAttributeDefinitions provides byte[] encodings of commonly used EAP Messages.
 *
 * @ee <a href="https://tools.ietf.org/html/rfc4186#section-10">RFC 4186, EAP-SIM Authentication,
 * Section 10</a>
 * @see <a href="https://tools.ietf.org/html/rfc4187#section-10">RFC 4187, EAP-AKA Authentication,
 * Section 10</a>
 */
public class EapTestAttributeDefinitions {
    public static final String VERSION = "0001";
    public static final String AT_VERSION_LIST_DATA = "0002" + VERSION + "0000";
    public static final byte[] AT_VERSION_LIST =
            hexStringToByteArray("0F02" + AT_VERSION_LIST_DATA);
    public static final byte[] AT_SELECTED_VERSION = hexStringToByteArray("10010001");

    public static final byte[] AT_VERSION_LIST_INVALID_LENGTH = hexStringToByteArray("0F020003");
    public static final byte[] AT_SELECTED_VERSION_INVALID_LENGTH =
            hexStringToByteArray("10020001");

}
