/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.internal.net.eap;

import static com.android.internal.net.TestUtils.hexStringToByteArray;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.net.eap.EapSessionConfig;

import com.android.internal.net.eap.crypto.TlsSession;
import com.android.internal.net.eap.crypto.TlsSessionFactory;
import com.android.internal.net.eap.statemachine.EapStateMachine;
import com.android.internal.net.eap.statemachine.EapTtlsMethodStateMachine;

import org.junit.AfterClass;
import org.junit.Before;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

public class EapTtlsTest extends EapMethodEndToEndTest {
    private static final long AUTHENTICATOR_TIMEOUT_MILLIS = 250L;

    // TUNNELED MSCHAPV2 (Phase 2)

    private static final String MSCHAPV2_USERNAME = "mschapv2.android.net";
    private static final String MSCHAPV2_PASSWORD = "mschappwd";
    private static final byte[] PEER_CHALLENGE =
            hexStringToByteArray("6592788337ED192AA396532E0AE65579");
    private static final byte[] MSCHAPV2_MSK =
            hexStringToByteArray(
                    "FA90B81CFF52D4FE37E029C84EC1E8B442AE19E482B0CA63FAEFF833C2DC86E60000"
                            + "000000000000000000000000000000000000000000000000000000000000");
    private static final int EMSK_LEN = 64;
    private static final byte[] MSCHAPV2_EMSK = new byte[EMSK_LEN];

    // TLSv1.2 Handshake Messages

    private static final String CLIENT_HELLO_STRING =
            "1603010085010000810303DE76A65F038E90315BB25B49CB9AB4E2540586C3B25851604C8D6E"
                    + "FECA11C16D00001CC02BC02CCCA9C02FC030CCA8C009C00AC013C014009C009D00"
                    + "2F00350100003C00170000FF01000100000A00080006001D00170018000B000201"
                    + "00000500050100000000000D001400120403080404010503080505010806060102"
                    + "01";
    private static final byte[] CLIENT_HELLO_BYTES = hexStringToByteArray(CLIENT_HELLO_STRING);

    private static final String SERVER_HELLO_INITIAL_FRAGMENT_STRING =
            "16030304140200003603035F46FED4999A26EE4CA1E4DB034E3BADAD262359A36885E19187F8"
                    + "5454F08E9E105188276593B74D74C1E95C9779EE83E9002F000B00037300037000"
                    + "036D3082036930820251A0030201020208570C6688A0ABF919300D06092A864886"
                    + "F70D01010B05003042310B30090603550406130255533110300E060355040A1307"
                    + "416E64726F69643121301F06035504031318726F6F742E63612E746573742E616E"
                    + "64726F69642E6E6574301E170D3230303530393031323331305A170D3233303530"
                    + "393031323331305A3045310B30090603550406130255533110300E060355040A13"
                    + "07416E64726F6964312430220603550403131B7365727665722E746573742E696B"
                    + "652E616E64726F69642E6E657430820122300D06092A864886F70D010101050003"
                    + "82010F003082010A0282010100C66872A68B0CFDD8453EF987A62AA4F9B251DB27"
                    + "F0E4079686CA678EE2090755F7FD314245398B2EC43C5464509D2298940609DABE"
                    + "57A60610D3DAF80D801B1F02F6A1262D92D333A9AC76D89951EF7733647E03DD44"
                    + "ED2A4EC274BB5CD4D3C55D8166949F6E13F4C3D695EF5F08FDBDD629F2D56E96CD"
                    + "91BFE84136D80CE274F516AC8CA69D6CAF9B762C8771F96A434783C2F02EC71317"
                    + "AEC38C0E058EA65A9E2E12B5AA0C505F40D237773C29C9246D9EE3152925F941C8"
                    + "FA67E6EA2A6B408009D9A9DA0B7A09F8B016C42C3156D5060DAA9F5081D24EF4FF"
                    + "51DA523C2D9BCA71DDB207CCC9DBE24AD447E1F44AF386A16745CD41CDBB01C4A2"
                    + "416E9A595D0203010001A360305E301F0603551D23041830168014499FA84785D7"
                    + "8363F757A422947EB1584212801A30260603551D11041F301D821B736572766572"
                    + "2E746573742E696B652E616E64726F69642E6E657430130603551D25040C300A06"
                    + "082B06010505070301300D06092A864886F70D01010B050003820101007067F0B9"
                    + "9698CA73410D703C83D294646D8734EF92C6CCBBE5E80A37A2B57DDD471739A8E2"
                    + "5BF03C3BB571CEBA423B80B294AAD8341690A9094D680910057B36C5AF58431421"
                    + "AE038A71A56FC9EA1C1B160C6B97F7326B364A0A5033A818DC37EDE5031FCF7D75"
                    + "2683DAAFDE59FBB030F754F3D32FBCCD74D7A594967F2F8E2A921099689A61B7BF"
                    + "9678F48F817BCF873B04A45112A17A4818981E7BF83F1DCB038C000DDCFD372A9D"
                    + "00DADC7A43A5DA3C9C0BB36111844A72110CE7B3CED711705D5774B64C2419AAF7"
                    + "888BBBC093CA0B7CFA8E118279B2AE30C0D28E0EE203B1D9DE34C29E58A8BA50B5"
                    + "4CBB917CFFC87604C2646CFFB7511A557F951CDD4E0D00005B020140000E000C04"
                    + "0105010601030102010101004600443042310B3009060355040613025553311030"
                    + "0E060355040A1307416E64726F69643121301F";
    private static final byte[] SERVER_HELLO_INITIAL_FRAGMENT_BYTES =
            hexStringToByteArray(SERVER_HELLO_INITIAL_FRAGMENT_STRING);
    private static final String SERVER_HELLO_FINAL_FRAGMENT_STRING =
            "06035504031318726F6F742E63612E746573742E616E64726F69642E6E65740E000000";
    private static final byte[] SERVER_HELLO_FINAL_FRAGMENT_BYTES =
            hexStringToByteArray(SERVER_HELLO_FINAL_FRAGMENT_STRING);
    private static final byte[] SERVER_HELLO_BYTES =
            hexStringToByteArray(
                    SERVER_HELLO_INITIAL_FRAGMENT_STRING + SERVER_HELLO_FINAL_FRAGMENT_STRING);

    private static final String CLIENT_FINISHED_STRING =
            "16030300070B0000030000001603030106100001020100A061D18580E2ACA2FDBB714012D180C"
                    + "595CB51ED7B89EF394CFF7265C68756CF55CBEE47284A0992B3FC64A77F28E5E98F"
                    + "B4F681BD67A87CD4DA115D70C74F96EB7AFCA822C0000824AA6C73DAA1233535EE0"
                    + "B63D0E52F5EB645BC617170957B68ADEDE770559899813C0F174787F0C73ED87A2A"
                    + "ED88D3C4438D8990D16DE9D6125EA772342123609941DD99CDE4A79E24D6C300AE5"
                    + "245266275EA73B5FE4955ED7C25D34D60E7E925B33EDA75BE14A5B16FC45E7E6BDA"
                    + "11C449A21D7455DD42D6B9418D04210CF50FD7D0A2B79882A4BE3EE68C2E9149F65"
                    + "465432B483255B1D0076F74030D252131FE92DEB72B7FA40DE649F51AAE4BC28A31"
                    + "ED8670E3AC221403030001011603030040016BFABBF2C74A11DDCFAFC8D815FA7C0"
                    + "B4D8705A4BC44699242B5C4D413A1EEDBAAD2F1951713E35B35A99D9B3EA916F12F"
                    + "297CEEC349173FE75C1B87F1CD66";
    private static final byte[] CLIENT_FINISHED_BYTES =
            hexStringToByteArray(CLIENT_FINISHED_STRING);

    private static final String SERVER_FINISHED_STRING =
            "14030300010116030300404570EA39954A9A370FDFCADC5DEDC072B9C204974645FD9D3E22383"
                    + "26B76D2160F6EB88433C2E64FEB0F9204AC963D92399417166EC7CBF2E4F723C879"
                    + "0C1255";
    private static final byte[] SERVER_FINISHED_BYTES =
            hexStringToByteArray(SERVER_FINISHED_STRING);

    // Phase 2 Messages (EAP-MSCHAPV2)

    private static final String ENCRYPTED_EAP_IDENTITY_AVP_STRING =
            "170303004070739851715B5BA7CC0237522560F811BFB47A7877E6882B524A3225B30EED1C66E7"
                    + "BE834C94B411995CF01C824E19B51E9E6D17AB273E218733071390D16752";
    private static final byte[] ENCRYPTED_EAP_IDENTITY_AVP_BYTES =
            hexStringToByteArray(ENCRYPTED_EAP_IDENTITY_AVP_STRING);
    private static final String DECRYPTED_EAP_IDENTITY_AVP_STRING =
            "0000004F" + "40" + "00000D" // AVP Code | AVP Flags | AVP Length
                    + "0210000501" // EAP-Response/Identity
                    + "000000"; // Padding
    private static final byte[] DECRYPTED_EAP_IDENTITY_AVP_BYTES =
            hexStringToByteArray(DECRYPTED_EAP_IDENTITY_AVP_STRING);

    private static final String EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_REQUEST_AVP_STRING =
            "1703030060AB010671AA326B4421D4F7336C476D0595E7C9104ADD9975FAC10CDA63DB82DB989F7"
                    + "6A6E41C2FAFE6C4C3BA4D4F49F08FF1FC88F0AD47BA9913D962A2D6F0C95D68AE879E"
                    + "A305FFE6A9D999C79A4B20D3B4C067A0E17F848D44C16AF61B27F5";
    private static final byte[] EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_REQUEST_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_REQUEST_AVP_STRING);
    private static final String EAP_MSCHAP_V2_DECRYPTED_CHALLENGE_REQUEST_AVP_STRING =
            "0000004F" + "40" + "00002C" // AVP Code | AVP Flags | AVP Length
                    + "01640024" // EAP-Request | ID | length in bytes
                    + "1A0164" // EAP-MSCHAPv2 | Request | MSCHAPv2 ID
                    + "001F10" // MS length | Value Size (0x10)
                    + "DCB648175C0A8200F226F94F0964F9DE" // Authenticator-Challenge
                    + "6D736368617074657374"; // Server-Name hex("mschaptest")
    private static final byte[] EAP_MSCHAP_V2_DECRYPTED_CHALLENGE_REQUEST_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_DECRYPTED_CHALLENGE_REQUEST_AVP_STRING);

    private static final String EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_RESPONSE_AVP_STRING =
            "17030300805D5941EECB4D1F040B3C199FBB078393220526B3C7A7F73D16C0D45EBE56CBA1E80E0"
                    + "1EB5B56E367B27B211C05D3713E389516B14568FB95679F960D61B5620F23D49B2A8F"
                    + "999C308004B389111F49B56F3AFDFEE4765ADF2ADBBB82E7D5AE8D4E25FB10D67091E"
                    + "E39E3A39F0F1AFB720231E3D824565349550BC7988C4E2E39";
    private static final byte[] EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_RESPONSE_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_RESPONSE_AVP_STRING);
    private static final String EAP_MSCHAP_V2_DECRYPTED_CHALLENGE_RESPONSE_AVP_STRING =
            "0000004F" + "40" + "000057" // AVP Code | AVP Flags | AVP Length
                    + "0264004F" // EAP-Response | ID | length in bytes
                    + "1A0264" // EAP-MSCHAPv2 | Response | MSCHAPv2 ID
                    + "004A31" // MS length | Value Size (0x31)
                    + "6592788337ED192AA396532E0AE65579" // Peer-Challenge
                    + "0000000000000000" // 8B (reserved)
                    + "6027E628F0090D596D4FF5FE451FC537CD54F7BD70F05C73" // NT-Response
                    + "00" // Flags
                    + "6D736368617076322E616E64726F69642E6E657400"; // hex(USERNAME)
    private static final byte[] EAP_MSCHAP_V2_DECRYPTED_CHALLENGE_RESPONSE_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_DECRYPTED_CHALLENGE_RESPONSE_AVP_STRING);

    private static final String EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_REQUEST_AVP_STRING =
            "17030300800A7516313DA811E690BAF1E76B5C25A1B57B891FC03AECDE89B5C75044B3111966EF91"
                    + "49ADA96F0720C055C9A124001097F1BD5E9728A38CA160BA433A95077B5B5367EDF8E3"
                    + "2EAAD7CDDED43BBDAEC4C1AD2CC919D591B3A744CCE1868295AD5F0115E7443E74AEA4"
                    + "38CFF96E13ED36F0E539537CE676E251B82BA9B1153569";
    private static final byte[] EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_REQUEST_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_REQUEST_AVP_STRING);
    private static final String EAP_MSCHAP_V2_DECRYPTED_SUCCESS_REQUEST_AVP_STRING =
            "0000004F" + "40" + "000051" // AVP Code | AVP Flags | AVP Length
                    + "01650049" // EAP-Request | ID | length in bytes
                    + "1A03640044" // EAP-MSCHAPv2 | Success | MSCHAPv2 ID | MS length
                    + "533D" // hex("S=")
                    + "3744354237394335353736334632433341323442"
                    + "4345334134323845353245364430314146444636" // hex("<auth_string>")
                    + "204D3D" // hex(" M=")
                    + "57656C636F6D65326561706D73636861703200000000"; // hex("Welcome2eapmschap2")
    private static final byte[] EAP_MSCHAP_V2_DECRYPTED_SUCCESS_REQUEST_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_DECRYPTED_SUCCESS_REQUEST_AVP_STRING);

    private static final String EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_RESPONSE_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3316F923AB2108DF93ECFA70192A852485E6D"
                    + "69105B0C57E2C57780C9C8D74BE705CC87F5C862FF30C1138390C8BE73";
    private static final byte[] EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_RESPONSE_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_RESPONSE_AVP_STRING);
    private static final String EAP_MSCHAP_V2_DECRYPTED_SUCCESS_RESPONSE_AVP_STRING =
            "0000004F" + "40" + "00000E" // AVP Code | AVP Flags | AVP Length
                    + "02650006" // EAP-Response | ID | length in bytes
                    + "1A030000"; // EAP-MSCHAPv2 | Success
    private static final byte[] EAP_MSCHAP_V2_DECRYPTED_SUCCESS_RESPONSE_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_DECRYPTED_SUCCESS_RESPONSE_AVP_STRING);

    private static final String EAP_MSCHAP_V2_ENCRYPTED_FAILURE_REQUEST_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3316F923AB2108DF93ECFA70192A852485E6D"
                    + "69105B0C57E2C57780C9C8D74BE705CC87F5C862FF30C1138390C8BE73";
    private static final byte[] EAP_MSCHAP_V2_ENCRYPTED_FAILURE_REQUEST_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_ENCRYPTED_FAILURE_REQUEST_AVP_STRING);
    private static final String EAP_MSCHAP_V2_DECRYPTED_FAILURE_REQUEST_AVP_STRING =
            "0000004F" + "40" + "000055" // AVP Code | AVP Flags | AVP Length
                    + "0113004D" // EAP-Request | ID | length in bytes
                    + "1A04420044" // EAP-MSCHAPv2 | Failure | MSCHAPv2 ID | MS length
                    + "453D363437" // hex("E=647")
                    + "20523D31" // hex(" R=1")
                    + "20433D" // hex(" C=")
                    + "30303031303230333034303530363037"
                    + "30383039304130423043304430453046" // hex("<authenticator challenge>")
                    + "20563D33" // hex(" V=3")
                    + "204D3D" // hex(" M=")
                    + "57656C636F6D65326561706D7363686170320000"; // hex("Welcome2eapmschap2")
    private static final byte[] EAP_MSCHAP_V2_DECRYPTED_FAILURE_REQUEST_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_DECRYPTED_FAILURE_REQUEST_AVP_STRING);

    private static final String EAP_MSCHAP_V2_ENCRYPTED_FAILURE_RESPONSE_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3316F923AB21074BE705CC87F5C862F85E6D83"
                    + "69105B0C57E2C57780CDA72CD43B3316F923AB21074BE70CC87F5C862F85E862F";
    private static final byte[] EAP_MSCHAP_V2_ENCRYPTED_FAILURE_RESPONSE_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_ENCRYPTED_FAILURE_RESPONSE_AVP_STRING);
    private static final String EAP_MSCHAP_V2_DECRYPTED_FAILURE_RESPONSE_AVP_STRING =
            "0000004F" + "40" + "00000E" // AVP Code | AVP Flags | AVP Length
                    + "02130006" // EAP-Response | ID | length in bytes
                    + "1A040000"; // EAP-MSCHAPv2 | Failure
    private static final byte[] EAP_MSCHAP_V2_DECRYPTED_FAILURE_RESPONSE_AVP_BYTES =
            hexStringToByteArray(EAP_MSCHAP_V2_DECRYPTED_FAILURE_RESPONSE_AVP_STRING);

    private static final String ENCRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3316F923AB21074BE705CC87F5C862F85E6D83"
                    + "F9F56678251443C56";
    private static final byte[] ENCRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_BYTES =
            hexStringToByteArray(ENCRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_STRING);
    private static final String DECRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_STRING =
            "0000004F" + "40" + "00000D" // AVP Code | AVP Flags | AVP Length
                    + "0110000517000000"; // AKA EAP-Identity Request
    private static final byte[] DECRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_BYTES =
            hexStringToByteArray(DECRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_STRING);

    private static final String ENCRYPTED_NAK_RESPONSE_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3316F923AB21074BE705CC87F5C862F85E6D83"
                    + "605B0C57E2C577923";
    private static final byte[] ENCRYPTED_NAK_RESPONSE_AVP_BYTES =
            hexStringToByteArray(ENCRYPTED_NAK_RESPONSE_AVP_STRING);
    private static final String DECRYPTED_NAK_RESPONSE_AVP_STRING =
            "0000004F" + "40" + "00000E" // AVP Code | AVP Flags | AVP Length
                    + "02100006031A0000"; // NAK
    private static final byte[] DECRYPTED_NAK_RESPONSE_AVP_BYTES =
            hexStringToByteArray(DECRYPTED_NAK_RESPONSE_AVP_STRING);


    private static final String ENCRYPTED_EAP_NOTIFICATION_REQUEST_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3316F923AB21074BE705CC87F5C862F85E6D83"
                    + "17E15E7443E74AEA4";
    private static final byte[] ENCRYPTED_EAP_NOTIFICATION_REQUEST_AVP_BYTES =
            hexStringToByteArray(ENCRYPTED_EAP_NOTIFICATION_REQUEST_AVP_STRING);
    private static final String DECRYPTED_EAP_NOTIFICATION_REQUEST_AVP_STRING =
            "0000004F" + "40" + "000010" // AVP Code | AVP Flags | AVP Length
                    + "0110000802AABBCC"; // Notification Request
    private static final byte[] DECRYPTED_EAP_NOTIFICATION_REQUEST_AVP_BYTES =
            hexStringToByteArray(DECRYPTED_EAP_NOTIFICATION_REQUEST_AVP_STRING);

    private static final String ENCRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_STRING =
            "1703030040CD43A46C500065962396E4BEDA72CD43B3317F923AB21074BE705CC87F1C862F85E6D83"
                    + "107FAA4BE705CCBE8";
    private static final byte[] ENCRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_BYTES =
            hexStringToByteArray(ENCRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_STRING);
    private static final String DECRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_STRING =
            "0000004F" + "40" + "00000D" // AVP Code | AVP Flags | AVP Length
                    + "0210000502000000"; // Notification Response
    private static final byte[] DECRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_BYTES =
            hexStringToByteArray(DECRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_STRING);

    // EAP-TTLS Request/Responses

    private static final byte[] EAP_RESPONSE_NAK_PACKET_TTLS = hexStringToByteArray("021000060315");
    private static final byte[] EAP_RESPONSE_NAK_PACKET_MSCHAPV2 =
            hexStringToByteArray("02080006031D");

    // Phase 1 (Handshake)

    private static final byte[] EAP_TTLS_START_REQUEST =
            hexStringToByteArray(
                    "01" + "10" + "0006" // EAP-Request | ID | length in bytes
                            + "1520"); // EAP-TTLS | flags);
    private static final byte[] EAP_TTLS_CLIENT_HELLO_RESPONSE =
            hexStringToByteArray(
                    "02" + "10" + "0094" // EAP-Response | ID | length in bytes
                            + "15800000008A" // EAP-TTLS | Flags | message length
                            + CLIENT_HELLO_STRING);
    private static final byte[] EAP_TTLS_SERVER_HELLO_REQUEST_INITIAL_FRAGMENT =
            hexStringToByteArray(
                    "01" + "10" + "0400" // EAP-Request | ID | length in bytes
                            + "15C000000419" // EAP-TTLS | Flags | message length
                            + SERVER_HELLO_INITIAL_FRAGMENT_STRING);
    private static final byte[] EAP_TTLS_ACKNOWLEDGEMENT_RESPONSE_SERVER_HELLO_FRAGMENT =
            hexStringToByteArray(
                    "02" + "10" + "0006" // EAP-Response | ID | length in bytes
                            + "1500"); // EAP-TTLS | Flags
    private static final byte[] EAP_TTLS_SERVER_HELLO_REQUEST_FINAL_FRAGMENT =
            hexStringToByteArray(
                    "01" + "10" + "0029" // EAP-Request | ID | length in bytes
                            + "1500" // EAP-TTLS | Flags
                            + SERVER_HELLO_FINAL_FRAGMENT_STRING);
    private static final byte[] EAP_TTLS_CLIENT_FINISHED_RESPONSE =
            hexStringToByteArray(
                    "02" + "10" + "016C" // EAP-Response | ID | length in bytes
                            + "158000000162" // EAP-TTLS | Flags | message length
                            + CLIENT_FINISHED_STRING);
    private static final byte[] EAP_TTLS_SERVER_FINISHED_REQUEST =
            hexStringToByteArray(
                    "01" + "10" + "0055" // EAP-Request | ID | length in bytes
                            + "15800000004B" // EAP-TTLS | Flags | message length
                            + SERVER_FINISHED_STRING);

    // Phase 2 (Tunnel)

    private static final byte[] EAP_TTLS_TUNNELED_IDENTITY_RESPONSE =
            hexStringToByteArray(
                    "02" + "10" + "004F" // EAP-Response | ID | length in bytes
                            + "158000000045" // EAP-TTLS | Flags | message length
                            + ENCRYPTED_EAP_IDENTITY_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_CHALLENGE_REQUEST =
            hexStringToByteArray(
                    "01" + "05" + "006F" // EAP-Request | ID | length in bytes
                            + "158000000065" // EAP-TTLS | Flags | message length
                            + EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_REQUEST_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_CHALLENGE_RESPONSE =
            hexStringToByteArray(
                    "02" + "05" + "008F" // EAP-Response | ID | length in bytes
                            + "158000000085" // EAP-TTLS | Flags | message length
                            + EAP_MSCHAP_V2_ENCRYPTED_CHALLENGE_RESPONSE_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_SUCCESS_REQUEST =
            hexStringToByteArray(
                    "01" + "06" + "008F" // EAP-Request | ID | length in bytes
                            + "158000000085" // EAP-TTLS | Flags | message length
                            + EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_REQUEST_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_SUCCESS_RESPONSE =
            hexStringToByteArray(
                    "02" + "06" + "004F" // EAP-Response | ID | length in bytes
                            + "158000000045" // EAP-TTLS | Flags | message length
                            + EAP_MSCHAP_V2_ENCRYPTED_SUCCESS_RESPONSE_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_FAILURE_REQUEST =
            hexStringToByteArray(
                    "01" + "07" + "004F" // EAP-Request | ID | length in bytes
                            + "158000000045" // EAP-TTLS | Flags | message length
                            + EAP_MSCHAP_V2_ENCRYPTED_FAILURE_REQUEST_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_FAILURE_RESPONSE =
            hexStringToByteArray(
                    "02" + "07" + "0053" // EAP-Response | ID | length in bytes
                            + "158000000049" // EAP-TTLS | Flags | message length
                            + EAP_MSCHAP_V2_ENCRYPTED_FAILURE_RESPONSE_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_AKA_IDENTITY_AVP_REQUEST =
            hexStringToByteArray(
                    "01" + "08" + "003B" // EAP-Request | ID | length in bytes
                            + "158000000031" // EAP-TTLS | Flags | message length
                            + ENCRYPTED_EAP_AKA_IDENTITY_REQUEST_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_NAK_RESPONSE =
            hexStringToByteArray(
                    "02" + "08"  + "003B" // EAP-Response | ID | length in bytes
                            + "158000000031" // EAP-TTLS | Flags | message length
                            + ENCRYPTED_NAK_RESPONSE_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_EAP_NOTIFICATION_REQUEST =
            hexStringToByteArray(
                    "01" + "08" + "003B" // EAP-Response | ID | length in bytes
                            + "158000000031" // EAP-TTLS | Flags | message length
                            + ENCRYPTED_EAP_NOTIFICATION_REQUEST_AVP_STRING);
    private static final byte[] EAP_TTLS_TUNNELED_EAP_NOTIFICATION_RESPONSE =
            hexStringToByteArray(
                    "02" + "08" + "003B" // EAP-Response | ID | length in bytes
                            + "158000000031" // EAP-TTLS | Flags | message length
                            + ENCRYPTED_EAP_NOTIFICATION_RESPONSE_AVP_STRING);

    private static final int APPLICATION_BUFFER_SIZE_TLS_MESSAGE = 16384;
    private static final int PACKET_BUFFER_SIZE_TLS_MESSAGE = 16384;

    private final TlsSessionFactory mMockTlsSessionFactory = mock(TlsSessionFactory.class);
    private final SSLEngine mMockSslEngine = mock(SSLEngine.class);
    private final SSLSession mMockSslSession = mock(SSLSession.class);

    @Before
    @Override
    public void setUp() {
        super.setUp();
        EapSessionConfig innerEapSessionConfig =
                new EapSessionConfig.Builder()
                        .setEapMsChapV2Config(MSCHAPV2_USERNAME, MSCHAPV2_PASSWORD)
                        .build();
        mEapSessionConfig =
                new EapSessionConfig.Builder()
                        .setEapTtlsConfig(null, innerEapSessionConfig)
                        .build();
        mEapAuthenticator =
                new EapAuthenticator(
                        mTestLooper.getLooper(),
                        mMockCallback,
                        new EapStateMachine(mMockContext, mEapSessionConfig, mMockSecureRandom),
                        Runnable::run,
                        AUTHENTICATOR_TIMEOUT_MILLIS);

        when(mMockSslSession.getApplicationBufferSize())
                .thenReturn(APPLICATION_BUFFER_SIZE_TLS_MESSAGE);
        when(mMockSslSession.getPacketBufferSize()).thenReturn(PACKET_BUFFER_SIZE_TLS_MESSAGE);
        TlsSession tlsSession =
                new TlsSession(
                        mock(SSLContext.class), mMockSslEngine, mMockSslSession, mMockSecureRandom);

        EapTtlsMethodStateMachine.sTlsSessionFactory = mMockTlsSessionFactory;
        try {
            when(mMockTlsSessionFactory.newInstance(eq(null), eq(mMockSecureRandom)))
                    .thenReturn(tlsSession);
        } catch (Exception e) {
            fail("TLS Session setup failed");
        }
    }

    @AfterClass
    public static void teardown() {
        EapTtlsMethodStateMachine.sTlsSessionFactory = new TlsSessionFactory();
    }
}
