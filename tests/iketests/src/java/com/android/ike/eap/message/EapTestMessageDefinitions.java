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

package com.android.ike.eap.message;

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.AT_VERSION_LIST_DATA;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.IDENTITY_STRING;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.NONCE_MT_STRING;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_1;
import static com.android.ike.eap.message.simaka.attributes.EapTestAttributeDefinitions.RAND_2;

import java.util.Arrays;

/**
 * EapTestMessageDefinitions provides byte[] encodings of commonly used EAP Messages.
 *
 * @see <a href="https://tools.ietf.org/html/rfc3748#section-4">RFC 3748, Extensible Authentication
 * Protocol (EAP)</a>
 */
public class EapTestMessageDefinitions {
    public static final String ID = "10";
    public static final int ID_INT = Integer.parseInt(ID, 16 /* radix */);

    // EAP-AKA Identity request
    public static final String EAP_REQUEST_TYPE_DATA = "0500000D010000";
    public static final byte[] EAP_AKA_IDENTITY_REQUEST =
            hexStringToByteArray(EAP_REQUEST_TYPE_DATA);
    public static final byte[] EAP_REQUEST_AKA_IDENTITY_PACKET =
            hexStringToByteArray("01" + ID + "000A17" + EAP_REQUEST_TYPE_DATA);
    public static final byte[] EAP_REQUEST_IDENTITY_PACKET =
            hexStringToByteArray("01" + ID + "000501");

    // EAP-Identity: hex for ASCII in "test@android.net"
    public static final String EAP_IDENTITY_STRING = "7465737440616E64726F69642E6E6574";
    public static final byte[] EAP_IDENTITY = hexStringToByteArray(EAP_IDENTITY_STRING);
    public static final byte[] EAP_RESPONSE_IDENTITY_PACKET =
            hexStringToByteArray("02" + ID + "001501" + EAP_IDENTITY_STRING);
    public static final byte[] EAP_RESPONSE_IDENTITY_DEFAULT_PACKET =
            hexStringToByteArray("02" + ID + "000501");
    public static final byte[] EAP_REQUEST_NOTIFICATION_PACKET =
            hexStringToByteArray("01" + ID + "000802AABBCC");
    public static final byte[] EAP_SUCCESS_PACKET = hexStringToByteArray("03" + ID + "0004");
    public static final byte[] EAP_FAILURE_PACKET = hexStringToByteArray("04" + ID + "0004");
    public static final byte[] EAP_SIM_CLIENT_ERROR_RESPONSE =
            hexStringToByteArray("02" + ID + "000C120E000016010001");
    public static final byte[] EAP_SIM_CLIENT_ERROR_INSUFFICIENT_CHALLENGES =
            hexStringToByteArray("02" + ID + "000C120E000016010002");
    public static final byte[] EAP_SIM_CLIENT_ERROR_UNABLE_TO_PROCESS =
            hexStringToByteArray("02" + ID + "000C120E000016010000");
    public static final byte[] EAP_AKA_CLIENT_ERROR_UNABLE_TO_PROCESS =
            hexStringToByteArray("02" + ID + "000C170E000016010000");

    // EAP-SIM response containing SELECTED_VERSION (1) and IDENTITY attributes
    public static final byte[] EAP_SIM_RESPONSE_PACKET = hexStringToByteArray(
            "02" + ID + "0024120A0000100100010E060011" + IDENTITY_STRING + "000000");
    public static final byte[] EAP_SIM_NOTIFICATION_RESPONSE = hexStringToByteArray(
            "02" + ID + "0008120C0000");

    // Body of EapData is the list of supported methods
    public static final byte[] EAP_RESPONSE_NAK_PACKET =
            hexStringToByteArray("02" + ID + "00060312");
    public static final byte[] EAP_RESPONSE_NOTIFICATION_PACKET =
            hexStringToByteArray("02" + ID + "000502");
    public static final byte[] EAP_REQUEST_MD5_CHALLENGE =
            hexStringToByteArray("01" + ID + "000504");
    public static final byte[] EAP_REQUEST_NAK_PACKET =
            hexStringToByteArray("01" + ID + "000503");
    public static final String EAP_REQUEST_SIM_TYPE_DATA = "0A00000F02000200010000";
    public static final byte[] EAP_REQUEST_SIM_START_PACKET =
            hexStringToByteArray("01" + ID + "001012" + EAP_REQUEST_SIM_TYPE_DATA);

    public static final byte[] REQUEST_UNSUPPORTED_TYPE_PACKET =
            hexStringToByteArray("01" + ID + "0005FF");
    public static final byte[] REQUEST_MISSING_TYPE_PACKET =
            hexStringToByteArray("01" + ID + "0004");
    public static final byte[] LONG_SUCCESS_PACKET = hexStringToByteArray("03" + ID + "000500");
    public static final byte[] SHORT_PACKET = hexStringToByteArray("01" + ID + "0005");
    public static final byte[] INCOMPLETE_HEADER_PACKET = hexStringToByteArray("03" + ID);
    public static final byte[] INVALID_CODE_PACKET = hexStringToByteArray("F0" + ID + "0004");

    // Attributes
    public static final String SKIPPABLE_DATA = "112233445566";
    public static final byte[] SKIPPABLE_DATA_BYTES = hexStringToByteArray(SKIPPABLE_DATA);
    public static final byte[] SKIPPABLE_INVALID_ATTRIBUTE =
            hexStringToByteArray("FF02" + SKIPPABLE_DATA);
    public static final byte[] NON_SKIPPABLE_INVALID_ATTRIBUTE =
            hexStringToByteArray("7F010000");

    // Type-Data
    public static final byte[] EAP_SIM_START_SUBTYPE =
            hexStringToByteArray("0A00000F02" + AT_VERSION_LIST_DATA + "0A010000");
    public static final byte[] INVALID_SUBTYPE = hexStringToByteArray("FF");
    public static final byte[] TYPE_DATA_INVALID_AT_RAND =
            hexStringToByteArray("0A000001050000" + RAND_1);
    public static final byte[] SHORT_TYPE_DATA = hexStringToByteArray("0A");
    public static final byte[] TYPE_DATA_INVALID_ATTRIBUTE =
            hexStringToByteArray("0A00007F01");
    public static final byte[] EAP_SIM_START_DUPLICATE_ATTRIBUTES =
            hexStringToByteArray("0A00000F02" + "0A010000" + "0A010000");

    // RAND Challenge Results
    public static final String SRES_1 = "11223344";
    public static final byte[] SRES_1_BYTES = hexStringToByteArray(SRES_1);
    public static final String SRES_2 = "44332211";
    public static final byte[] SRES_2_BYTES = hexStringToByteArray(SRES_2);
    public static final byte[] SRES_BYTES = hexStringToByteArray(SRES_1 + SRES_2);
    public static final String KC_1 = "0102030405060708";
    public static final byte[] KC_1_BYTES = hexStringToByteArray(KC_1);
    public static final String KC_2 = "0807060504030201";
    public static final byte[] KC_2_BYTES = hexStringToByteArray(KC_2);
    public static final byte[] VALID_CHALLENGE_RESPONSE =
            hexStringToByteArray("04" + SRES_1 + "08" + KC_1);
    public static final byte[] CHALLENGE_RESPONSE_INVALID_SRES = hexStringToByteArray("03");
    public static final byte[] CHALLENGE_RESPONSE_INVALID_KC =
            hexStringToByteArray("04" + SRES_1 + "04");

    public static final String IMSI = "123456789012345";
    public static final String EAP_SIM_IDENTITY = "1" + IMSI;
    public static final byte[] EAP_SIM_IDENTITY_BYTES = hexStringToByteArray(EAP_SIM_IDENTITY);

    // Master Key generation
    public static final String MK_STRING = "0123456789ABCDEF0123456789ABCDEF01234567";
    public static final byte[] MK = hexStringToByteArray(MK_STRING);
    public static final String K_ENCR_STRING = "000102030405060708090A0B0C0D0E0F";
    public static final byte[] K_ENCR = hexStringToByteArray(K_ENCR_STRING);
    public static final String K_AUT_STRING = "0F0E0D0C0B0A09080706050403020100";
    public static final byte[] K_AUT = hexStringToByteArray(K_AUT_STRING);
    public static final String MSK_STRING =
            "00112233445566778899AABBCCDDEEFF"
            + "00112233445566778899AABBCCDDEEFF"
            + "00112233445566778899AABBCCDDEEFF"
            + "00112233445566778899AABBCCDDEEFF";
    public static final byte[] MSK = hexStringToByteArray(MSK_STRING);
    public static final String EMSK_STRING =
            "FFEEDDCCBBAA99887766554433221100"
            + "FFEEDDCCBBAA99887766554433221100"
            + "FFEEDDCCBBAA99887766554433221100"
            + "FFEEDDCCBBAA99887766554433221100";
    public static final byte[] EMSK = hexStringToByteArray(EMSK_STRING);

    // MAC computation
    public static final String ORIGINAL_MAC_STRING = "112233445566778899AABBCCDDEEFF11";
    public static final byte[] ORIGINAL_MAC = hexStringToByteArray(ORIGINAL_MAC_STRING);
    public static final String COMPUTED_MAC_STRING = "FFEEDDCCBBAA998877665544332211FF";
    public static final byte[] COMPUTED_MAC = hexStringToByteArray(COMPUTED_MAC_STRING);
    public static final byte[] RETURNED_MAC = Arrays.copyOf(COMPUTED_MAC, 16);
    public static final String EAP_SIM_CHALLENGE_REQUEST_STRING =
            "01" + ID + "0040" // EAP-Request | ID | length in bytes
            + "120b0000" // EAP-SIM | Challenge | 2B padding
            + "01090000" + RAND_1 + RAND_2 // EAP-SIM AT_RAND attribute
            + "0B05000000000000000000000000000000000000"; // AT_MAC attribute with no MAC
    public static final byte[] MAC_INPUT =
            hexStringToByteArray(EAP_SIM_CHALLENGE_REQUEST_STRING + NONCE_MT_STRING);

    // Response Message with MAC
    public static final String EAP_SIM_CHALLENGE_RESPONSE_EMPTY_MAC =
            "02" + ID + "001C" // EAP-Response | ID | length in bytes
            + "120b0000" // EAP-SIM | Challenge | 2B padding
            + "0B05000000000000000000000000000000000000"; // AT_MAC attribute with no MAC
    public static final byte[] EAP_SIM_CHALLENGE_RESPONSE_MAC_INPUT =
            hexStringToByteArray(EAP_SIM_CHALLENGE_RESPONSE_EMPTY_MAC + SRES_1 + SRES_2);
    public static final byte[] EAP_SIM_CHALLENGE_RESPONSE_WITH_MAC = hexStringToByteArray(
            "02" + ID + "001C" // EAP-Response | ID | length in bytes
            + "120b0000" // EAP-SIM | Challenge | 2B padding
            + "0B050000" + COMPUTED_MAC_STRING); // AT_MAC attribute
    public static final byte[] EAP_SIM_NOTIFICATION_REQUEST_WITH_EMPTY_MAC = hexStringToByteArray(
            "01" + ID + "0020" // EAP-Request | ID | length in bytes
                    + "120C0000" // EAP-SIM | Notification | 2B padding
                    + "0C010000" // AT_NOTIFICATION attribute
                    + "0B05000000000000000000000000000000000000"); // empty AT_MAC attribute
    public static final byte[] EAP_SIM_NOTIFICATION_RESPONSE_WITH_EMPTY_MAC = hexStringToByteArray(
            "02" + ID + "001C" // EAP-Response | ID | length in bytes
                    + "120C0000" // EAP-SIM | Notification | 2B padding
                    + "0B05000000000000000000000000000000000000"); // empty AT_MAC attribute
    public static final byte[] EAP_SIM_NOTIFICATION_RESPONSE_WITH_MAC = hexStringToByteArray(
            "02" + ID + "001C" // EAP-Response | ID | length in bytes
            + "120C0000" // EAP-SIM | Notification | 2B padding
            + "0B050000" + COMPUTED_MAC_STRING); // AT_MAC attribute

}
