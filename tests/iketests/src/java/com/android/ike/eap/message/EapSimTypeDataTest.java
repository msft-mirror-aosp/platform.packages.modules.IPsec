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

import static com.android.ike.eap.message.EapTestMessageDefinitions.INVALID_SUBTYPE;
import static com.android.ike.eap.message.EapTestMessageDefinitions.SHORT_TYPE_DATA;
import static com.android.ike.eap.message.EapTestMessageDefinitions.TYPE_DATA_INVALID_ATTRIBUTE;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapSimInvalidTypeDataException;
import com.android.ike.eap.exceptions.EapSimUnsupportedAttributeException;

import org.junit.Test;

import java.nio.BufferUnderflowException;

public class EapSimTypeDataTest {
    @Test
    public void testDecodeNullTypeData() throws Exception {
        try {
            EapSimTypeData.decode(null);
            fail("Expected IllegalArgumentException for null typeData");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testDecodeInvalidSubtype() {
        try {
            EapSimTypeData.decode(INVALID_SUBTYPE);
            fail("Expected EapSimInvalidTypeDataException for invalid EAP Subtype");
        } catch (EapSimInvalidTypeDataException expected) {
        }
    }

    @Test
    public void testDecodeShortPacket() {
        try {
            EapSimTypeData.decode(SHORT_TYPE_DATA);
            fail("Expected EapSimInvalidTypeDataException for incomplete EapSimTypeData in byte[]");
        } catch (EapSimInvalidTypeDataException expected) {
            assertTrue(expected.getCause() instanceof BufferUnderflowException);
        }
    }

    @Test
    public void testDecodeInvalidEapAttribute() {
        try {
            EapSimTypeData.decode(TYPE_DATA_INVALID_ATTRIBUTE);
            fail("Expected EapSimInvalidTypeDataException for invalid EAP Attribute");
        } catch (EapSimInvalidTypeDataException expected) {
            assertTrue(expected.getCause() instanceof EapSimUnsupportedAttributeException);
        }
    }
}
