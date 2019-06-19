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
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_RAND;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_RAND;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_RAND_DUPLICATE_RANDS;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_RAND_INVALID_NUM_RANDS;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_1;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.RAND_2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapSimInvalidAtRandException;
import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtRand;
import com.android.ike.eap.message.EapSimAttributeFactory;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class AtRandTest {
    private static final int EXPECTED_NUM_RANDS = 2;

    private EapSimAttributeFactory mEapSimAttributeFactory;

    @Before
    public void setUp() {
        mEapSimAttributeFactory = EapSimAttributeFactory.getInstance();
    }

    @Test
    public void testDecode() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_RAND);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtRand);
        AtRand atRand = (AtRand) result;
        assertEquals(EAP_AT_RAND, atRand.attributeType);
        assertEquals(AT_RAND.length, atRand.lengthInBytes);
        assertEquals(EXPECTED_NUM_RANDS, atRand.rands.size());
        assertArrayEquals(hexStringToByteArray(RAND_1), atRand.rands.get(0));
        assertArrayEquals(hexStringToByteArray(RAND_2), atRand.rands.get(1));
    }

    @Test
    public void testDecodeInvalidNumRands() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_RAND_INVALID_NUM_RANDS);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAtRandException for invalid number of RANDs");
        } catch (EapSimInvalidAtRandException expected) {
        }
    }

    @Test
    public void testDecodeDuplicateRands() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_RAND_DUPLICATE_RANDS);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for duplicate RANDs");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncode() throws Exception {
        byte[][] expectedRands = new byte[][] {
                hexStringToByteArray(RAND_1),
                hexStringToByteArray(RAND_2)
        };
        AtRand atRand = new AtRand(AT_RAND.length, expectedRands);

        ByteBuffer result = ByteBuffer.allocate(AT_RAND.length);
        atRand.encode(result);
        assertArrayEquals(AT_RAND, result.array());
    }
}
