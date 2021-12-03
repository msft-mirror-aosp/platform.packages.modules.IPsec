/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.internal.net.eap.test.message.simaka.attributes;

import static com.android.internal.net.TestUtils.hexStringToByteArray;
import static com.android.internal.net.eap.test.message.simaka.EapSimAkaAttribute.EAP_AT_ENCR_DATA;
import static com.android.internal.net.eap.test.message.simaka.attributes.EapTestAttributeDefinitions.IV_BYTES;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.android.internal.net.eap.test.message.simaka.EapSimAkaAttribute;
import com.android.internal.net.eap.test.message.simaka.EapSimAkaAttribute.AtEncrData;
import com.android.internal.net.eap.test.message.simaka.EapSimAkaAttributeFactory;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class AtEncrDataTest {
    private static final int ATTR_HEADER_LEN = 4;

    private static final String DECRYPTED_DATA_HEX =
            "850D0030344F4C55705143714679686D312F5567443536616E547A5954714A44636B6962716A553650"
                    + "6C5334735A6169754C633D060300000000000000000000";
    private static final String ENCRYPTED_DATA_HEX =
            "67C558643A443C5CBE6E797E28C9C006E349A0EF11AD5ED9094A19B9AB8AF96DCFFB472737DC4E52"
                    + "E0783A92A51F4A88891A528AF2AB70E4C8CF7415F0A12CE8";

    private static final byte[] DECRYPTED_DATA = hexStringToByteArray(DECRYPTED_DATA_HEX);
    private static final byte[] ENCRYPTED_DATA = hexStringToByteArray(ENCRYPTED_DATA_HEX);
    private static final byte[] AT_ENCR_DATA =
            hexStringToByteArray("82110000" + ENCRYPTED_DATA_HEX);

    private static final byte[] KEY_ENCR = hexStringToByteArray("12345678123456781234567812345678");

    private EapSimAkaAttributeFactory mAttributeFactory;

    @Before
    public void setUp() throws Exception {
        mAttributeFactory = new EapSimAkaAttributeFactory() {};
    }

    @Test
    public void testDecode() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_ENCR_DATA);
        EapSimAkaAttribute result = mAttributeFactory.getAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtEncrData);
        AtEncrData atEncrData = (AtEncrData) result;
        assertEquals(EAP_AT_ENCR_DATA, atEncrData.attributeType);
        assertEquals(AT_ENCR_DATA.length, atEncrData.lengthInBytes);
        assertArrayEquals(ENCRYPTED_DATA, atEncrData.encrData);
    }

    @Test
    public void testEncryptAndEncode() throws Exception {
        AtEncrData atEncrData = new AtEncrData(DECRYPTED_DATA, KEY_ENCR, IV_BYTES);
        ByteBuffer result = ByteBuffer.allocate(DECRYPTED_DATA.length + ATTR_HEADER_LEN);
        atEncrData.encode(result);

        assertArrayEquals(AT_ENCR_DATA, result.array());
    }

    @Test
    public void testDecryptEncrData() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_ENCR_DATA);
        EapSimAkaAttribute result = mAttributeFactory.getAttribute(input);

        AtEncrData atEncrData = (AtEncrData) result;
        byte[] decryptedData = atEncrData.getDecryptedData(KEY_ENCR, IV_BYTES);
        assertArrayEquals(DECRYPTED_DATA, decryptedData);
    }
}
