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

import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_FULLAUTH_ID_REQ;
import static com.android.ike.eap.message.EapSimAttribute.EAP_AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.ANY_ID_INVALID_LENGTH;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_ANY_ID_REQ;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_FULL_AUTH_ID_REQ;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.FULL_AUTH_ID_INVALID_LENGTH;
import static com.android.ike.eap.message.attributes.EapTestAttributeDefinitions.PERMANENT_ID_INVALID_LENGTH;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.message.EapSimAttribute;
import com.android.ike.eap.message.EapSimAttribute.AtAnyIdReq;
import com.android.ike.eap.message.EapSimAttribute.AtFullauthIdReq;
import com.android.ike.eap.message.EapSimAttribute.AtPermanentIdReq;
import com.android.ike.eap.message.EapSimAttributeFactory;


import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;

public class AtIdReqTest {
    private static final int EXPECTED_LENGTH = 4;

    private EapSimAttributeFactory mEapSimAttributeFactory;

    @Before
    public void setUp() {
        mEapSimAttributeFactory = EapSimAttributeFactory.getInstance();
    }

    @Test
    public void testDecodeAtPermanentIdReq() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_PERMANENT_ID_REQ);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtPermanentIdReq);
        AtPermanentIdReq atPermanentIdReq = (AtPermanentIdReq) result;
        assertEquals(EAP_AT_PERMANENT_ID_REQ, atPermanentIdReq.attributeType);
        assertEquals(EXPECTED_LENGTH, atPermanentIdReq.lengthInBytes);
    }

    @Test
    public void testDecodeAtPermanentIdReqInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(PERMANENT_ID_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for invalid attribute length");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncodeAtPermanentIdReq() throws Exception {
        AtPermanentIdReq atPermanentIdReq = new AtPermanentIdReq();
        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);

        atPermanentIdReq.encode(result);
        assertArrayEquals(AT_PERMANENT_ID_REQ, result.array());
    }

    @Test
    public void testDecodeAtAnyIdReq() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_ANY_ID_REQ);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtAnyIdReq);
        AtAnyIdReq atAnyIdReq = (AtAnyIdReq) result;
        assertEquals(EAP_AT_ANY_ID_REQ, atAnyIdReq.attributeType);
        assertEquals(EXPECTED_LENGTH, atAnyIdReq.lengthInBytes);
    }

    @Test
    public void testDecodeAtAnyIdReqInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(ANY_ID_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for invalid attribute length");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncodeAtAnyIdReq() throws Exception {
        AtAnyIdReq atPermanentIdReq = new AtAnyIdReq();
        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);

        atPermanentIdReq.encode(result);
        assertArrayEquals(AT_ANY_ID_REQ, result.array());
    }

    @Test
    public void testDecodeAtFullauthIdReq() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(AT_FULL_AUTH_ID_REQ);
        EapSimAttribute result = mEapSimAttributeFactory.getEapSimAttribute(input);

        assertFalse(input.hasRemaining());
        assertTrue(result instanceof AtFullauthIdReq);
        AtFullauthIdReq atFullauthIdReq = (AtFullauthIdReq) result;
        assertEquals(EAP_AT_FULLAUTH_ID_REQ, atFullauthIdReq.attributeType);
        assertEquals(EXPECTED_LENGTH, atFullauthIdReq.lengthInBytes);
    }

    @Test
    public void testDecodeAtFullauthIdReqInvalidLength() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(FULL_AUTH_ID_INVALID_LENGTH);
        try {
            mEapSimAttributeFactory.getEapSimAttribute(input);
            fail("Expected EapSimInvalidAttributeException for invalid attribute length");
        } catch (EapSimInvalidAttributeException expected) {
        }
    }

    @Test
    public void testEncodeAtFullauthIdReq() throws Exception {
        AtFullauthIdReq atPermanentIdReq = new AtFullauthIdReq();
        ByteBuffer result = ByteBuffer.allocate(EXPECTED_LENGTH);

        atPermanentIdReq.encode(result);
        assertArrayEquals(AT_FULL_AUTH_ID_REQ, result.array());
    }
}
