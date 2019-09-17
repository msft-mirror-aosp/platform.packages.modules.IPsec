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

package com.android.ike.eap.message.mschapv2;

import static com.android.ike.TestUtils.hexStringToByteArray;

public class EapMsChapV2PacketDefinitions {
    public static final String ID = "1F";
    public static final int ID_INT = Integer.parseInt(ID, 16 /* radix */);

    public static final String CHALLENGE = "000102030405060708090A0B0C0D0E0F";
    public static final byte[] CHALLENGE_BYTES = hexStringToByteArray(CHALLENGE);

    // server name is the ASCII hex for "authenticator@android.net"
    public static final String SERVER_NAME = "61757468656E74696361746F7240616E64726F69642E6E6574";
    public static final byte[] SERVER_NAME_BYTES = hexStringToByteArray(SERVER_NAME);
    public static final byte[] EAP_MSCHAP_V2_CHALLENGE_REQUEST =
            hexStringToByteArray("01" + ID + "002E10" + CHALLENGE + SERVER_NAME);

    public static final byte[] CHALLENGE_REQUEST_WRONG_OP_CODE = hexStringToByteArray("02");
    public static final String SHORT_CHALLENGE = "001122334455";
    public static final byte[] CHALLENGE_REQUEST_SHORT_CHALLENGE =
            hexStringToByteArray("01" + ID + "002406" + SHORT_CHALLENGE + SERVER_NAME);
    public static final byte[] CHALLENGE_REQUEST_SHORT_MS_LENGTH =
            hexStringToByteArray("01" + ID + "000110" + CHALLENGE + SERVER_NAME);
    public static final byte[] CHALLENGE_REQUEST_LONG_MS_LENGTH =
            hexStringToByteArray("01" + ID + "00FF10" + CHALLENGE + SERVER_NAME);
}
