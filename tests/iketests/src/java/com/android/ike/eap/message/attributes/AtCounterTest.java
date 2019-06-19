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

import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_COUNTER;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_COUNTER_TOO_SMALL;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_COUNTER;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_COUNTER_INVALID_LENGTH;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_COUNTER_TOO_SMALL;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_COUNTER_TOO_SMALL_INVALID_LENGTH;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.COUNTER_INT;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtCounter;
import com.android.ike.eap.message.EapSimAttribute.AtCounterTooSmall;
import com.android.ike.eap.message.EapSimAttributeFactory;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class AtCounterTest {
    private static final int EXPECTED_LENGTH = 4;

    private EapSimAttributeFactory mEapSimAttributeFactory;

    @Before
    public void setUp() {
        mEapSimAttributeFactory = EapSimAttributeFactory.getInstance();
    }

    @Test
    public void testDecodeAtCounter() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_COUNTER);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtCounter);
        AtCounter atCounter = (AtCounter) result;
        assertEquals(EAP_AT_COUNTER, atCounter.attributeType);
        assertEquals(EXPECTED_LENGTH, atCounter.lengthInBytes);
        assertEquals(COUNTER_INT, atCounter.counter);
    }

    @Test
    public void testDecodeAtCounterInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_COUNTER_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for invalid length");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncodeAtCounter() throws Exception {
        AtCounter atCounter = new AtCounter(COUNTER_INT);

        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);
        atCounter.encode(result);
        assertArrayEquals(AT_COUNTER, result.array());
    }

    @Test
    public void testAtCounterTooSmallConstructor() throws Exception {
        AtCounterTooSmall atCounterTooSmall = new AtCounterTooSmall();
        assertEquals(EAP_AT_COUNTER_TOO_SMALL, atCounterTooSmall.attributeType);
        assertEquals(EXPECTED_LENGTH, atCounterTooSmall.lengthInBytes);
    }

    @Test
    public void testDecodeAtCounterTooSmall() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_COUNTER_TOO_SMALL);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtCounterTooSmall);
        AtCounterTooSmall atCounterTooSmall = (AtCounterTooSmall) result;
        assertEquals(EAP_AT_COUNTER_TOO_SMALL, atCounterTooSmall.attributeType);
        assertEquals(EXPECTED_LENGTH, atCounterTooSmall.lengthInBytes);
    }

    @Test
    public void testDecodeAtCounterTooSmallInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_COUNTER_TOO_SMALL_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for invalid length");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncodeAtCounterTooSmall() throws Exception {
        AtCounterTooSmall atCounterTooSmall = new AtCounterTooSmall();
        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);
        atCounterTooSmall.encode(result);
        assertArrayEquals(AT_COUNTER_TOO_SMALL, result.array());
    }
}
