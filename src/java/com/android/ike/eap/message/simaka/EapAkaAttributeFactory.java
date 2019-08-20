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

package com.android.ike.eap.message.simaka;

import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_RAND;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.LENGTH_SCALING;

import com.android.ike.eap.exceptions.simaka.EapSimAkaInvalidAttributeException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaUnsupportedAttributeException;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtRandAka;

import java.nio.ByteBuffer;

/**
 * EapAkaAttributeFactory is used for creating EAP-AKA attributes according to their type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4187">RFC 4187, Extensible Authentication
 * Protocol for Authentication and Key Agreement (EAP-AKA)</a>
 * @see <a href="https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml">EAP SIM/AKA
 * Attributes</a>
 */
public class EapAkaAttributeFactory extends EapSimAkaAttributeFactory {
    private static EapAkaAttributeFactory sInstance = new EapAkaAttributeFactory();

    private EapAkaAttributeFactory() {
    }

    public static EapAkaAttributeFactory getInstance() {
        return sInstance;
    }

    /**
     * Decodes a single EapSimAkaAttribute object from the given ByteBuffer.
     *
     * <p>Decoding logic is based on Attribute definitions in RFC 4187#10.
     *
     * @param byteBuffer The ByteBuffer to parse the current attribute from
     * @return The current EapSimAkaAttribute to be parsed, or EapSimAkaUnsupportedAttribute if the
     *         given attributeType is skippable and unsupported
     * @throws EapSimAkaInvalidAttributeException when a malformatted attribute is attempted to be
     *         decoded
     * @throws EapSimAkaUnsupportedAttributeException when an unsupported, unskippable Attribute is
     *         attempted to be decoded
     */
    public EapSimAkaAttribute getEapAkaAttribute(ByteBuffer byteBuffer) throws
            EapSimAkaInvalidAttributeException, EapSimAkaUnsupportedAttributeException {
        int attributeType = Byte.toUnsignedInt(byteBuffer.get());

        // Length is given as a multiple of 4x bytes (RFC 4187#8.1)
        int lengthInBytes = Byte.toUnsignedInt(byteBuffer.get()) * LENGTH_SCALING;

        switch (attributeType) {
            case EAP_AT_RAND:
                return new AtRandAka(lengthInBytes, byteBuffer);
            default:
                return super.getEapAttribute(attributeType, lengthInBytes, byteBuffer);
        }
    }
}
