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
import static com.android.ike.eap.message.EapTestMessageDefinitions.NON_SKIPPABLE_INVALID_ATTRIBUTE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SKIPPABLE_DATA;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SKIPPABLE_INVALID_ATTRIBUTE;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapSimUnsupportedAttributeException;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class EapSimAttributeFactoryTest {
    private static final int SKIPPABLE_ATTRIBUTE_TYPE = 0xFF;
    private static final int EXPECTED_LENGTH = 8;

    private EapSimAttributeFactory mEapSimAttributeFactory;

    @Before
    public void setUp() {
        mEapSimAttributeFactory = EapSimAttributeFactory.getInstance();
    }

    @Test
    public void testDecodeInvalidSkippable() throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(SKIPPABLE_INVALID_ATTRIBUTE);

        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(byteBuffer);
        assertTrue(result instanceof EapSimAttribute.EapSimUnsupportedAttribute);
        EapSimAttribute.EapSimUnsupportedAttribute
                eapSimUnsupportedAttribute = (EapSimAttribute.EapSimUnsupportedAttribute) result;
        assertEquals(SKIPPABLE_ATTRIBUTE_TYPE, eapSimUnsupportedAttribute.attributeType);
        assertEquals(EXPECTED_LENGTH, eapSimUnsupportedAttribute.lengthInBytes);
        assertArrayEquals(hexStringToByteArray(SKIPPABLE_DATA), eapSimUnsupportedAttribute.data);
    }

    @Test
    public void testEncodeInvalidSkippable() throws Exception {
        EapSimAttribute.EapSimUnsupportedAttribute
                eapSimUnsupportedAttribute = new EapSimAttribute.EapSimUnsupportedAttribute(
                SKIPPABLE_ATTRIBUTE_TYPE, EXPECTED_LENGTH, hexStringToByteArray(SKIPPABLE_DATA));

        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);
        eapSimUnsupportedAttribute.encode(result);
        assertArrayEquals(SKIPPABLE_INVALID_ATTRIBUTE, result.array());
    }

    @Test
    public void testDecodeInvalidNonSkippable() throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(NON_SKIPPABLE_INVALID_ATTRIBUTE);

        try {
            mEapSimAttributeFactory.getEapSimAttribute(byteBuffer);
            fail("Expected EapSimUnsupportedAttributeException for decoding invalid"
                    + " non-skippable Attribute");
        } catch (EapSimUnsupportedAttributeException expected) {
        }
    }
}
