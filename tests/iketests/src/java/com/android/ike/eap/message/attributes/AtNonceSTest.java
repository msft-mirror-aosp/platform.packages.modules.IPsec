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
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_NONCE_S;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_NONCE_S;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_NONCE_S_INVALID_LENGTH;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.NONCE_S;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtNonceS;
import com.android.ike.eap.message.EapSimAttributeFactory;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class AtNonceSTest {
    private static final int EXPECTED_LENGTH = 20;

    private EapSimAttributeFactory mEapSimAttributeFactory;

    @Before
    public void setUp() {
        mEapSimAttributeFactory = EapSimAttributeFactory.getInstance();
    }

    @Test
    public void testDecode() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_NONCE_S);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtNonceS);
        AtNonceS atNonceS = (AtNonceS) result;
        assertEquals(EAP_AT_NONCE_S, atNonceS.attributeType);
        assertEquals(EXPECTED_LENGTH, atNonceS.lengthInBytes);
        assertArrayEquals(hexStringToByteArray(NONCE_S), atNonceS.nonceS);
    }

    @Test
    public void testDecodeInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_NONCE_S_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for invalid length");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncode() throws Exception {
        AtNonceS atNonceS = new AtNonceS(hexStringToByteArray(NONCE_S));

        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);
        atNonceS.encode(result);
        assertArrayEquals(AT_NONCE_S, result.array());
    }
}
