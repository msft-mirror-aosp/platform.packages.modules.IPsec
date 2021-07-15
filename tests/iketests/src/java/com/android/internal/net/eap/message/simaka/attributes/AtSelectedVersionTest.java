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

package com.android.internal.net.eap.test.message.simaka.attributes;

import static com.android.internal.net.eap.test.message.simaka.EapSimAkaAttribute.EAP_AT_SELECTED_VERSION;
import static com.android.internal.net.eap.test.message.simaka.attributes.EapTestAttributeDefinitions.AT_SELECTED_VERSION;
import static com.android.internal.net.eap.test.message.simaka.attributes.EapTestAttributeDefinitions.AT_SELECTED_VERSION_INVALID_LENGTH;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.internal.net.eap.test.exceptions.simaka.EapSimAkaInvalidAttributeException;
import com.android.internal.net.eap.test.message.simaka.EapSimAkaAttribute;
import com.android.internal.net.eap.test.message.simaka.EapSimAkaAttribute.AtSelectedVersion;
import com.android.internal.net.eap.test.message.simaka.EapSimAttributeFactory;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class AtSelectedVersionTest {
    private static final int EXPECTED_LENGTH = 4;
    private static final int EXPECTED_VERSION = 1;

    private EapSimAttributeFactory mEapSimAttributeFactory;

    @Before
    public void setUp() {
        mEapSimAttributeFactory = EapSimAttributeFactory.getInstance();
    }


    @Test
    public void testDecode() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_SELECTED_VERSION);
        EapSimAkaAttribute result = mEapSimAttributeFactory.getAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtSelectedVersion);
        AtSelectedVersion atSelectedVersion = (AtSelectedVersion) result;
        assertEquals(EAP_AT_SELECTED_VERSION, atSelectedVersion.attributeType);
        assertEquals(EXPECTED_LENGTH, atSelectedVersion.lengthInBytes);
        assertEquals(EXPECTED_VERSION, atSelectedVersion.selectedVersion);
    }

    @Test
    public void testDecodeInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_SELECTED_VERSION_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getAttribute(input);
            fail("Expected EapSimAkaInvalidAttributeException for invalid actual list length");
        } catch (EapSimAkaInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncode() throws Exception {
        AtSelectedVersion atSelectedVersion = new AtSelectedVersion(
                EXPECTED_LENGTH, EXPECTED_VERSION);
        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);

        atSelectedVersion.encode(result);
        assertArrayEquals(AT_SELECTED_VERSION, result.array());
    }
}
