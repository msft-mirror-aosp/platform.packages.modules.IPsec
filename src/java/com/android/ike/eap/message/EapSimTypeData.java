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

import android.annotation.NonNull;
import android.util.Log;

import com.android.ike.eap.exceptions.EapSimInvalidAttributeException;
import com.android.ike.eap.exceptions.EapSimInvalidTypeDataException;
import com.android.ike.eap.exceptions.EapSimUnsupportedAttributeException;
import com.android.ike.eap.message.EapSimAttribute.EapSimUnsupportedAttribute;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;

/**
 * EapSimTypeData represents the Type Data for an {@link EapMessage} during an EAP-SIM session.
 */
public class EapSimTypeData {
    private static final String TAG = EapSimTypeData.class.getSimpleName();

    // EAP-SIM Subtype values defined by IANA
    // https://www.iana.org/assignments/eapsimaka-numbers/eapsimaka-numbers.xhtml
    public static final int EAP_SIM_START = 10;
    public static final int EAP_SIM_CHALLENGE = 11;
    public static final int EAP_SIM_NOTIFICATION = 12;
    public static final int EAP_SIM_REAUTHENTICATION = 13;
    public static final int EAP_SIM_CLIENT_ERROR = 14;

    private static final Set<Integer> SUPPORTED_SUBTYPES = new HashSet<>();
    static {
        SUPPORTED_SUBTYPES.add(EAP_SIM_START);
        SUPPORTED_SUBTYPES.add(EAP_SIM_CHALLENGE);
        SUPPORTED_SUBTYPES.add(EAP_SIM_NOTIFICATION);
        SUPPORTED_SUBTYPES.add(EAP_SIM_REAUTHENTICATION);
        SUPPORTED_SUBTYPES.add(EAP_SIM_CLIENT_ERROR);
    }

    public final int eapSubtype;

    // LinkedHashMap used to preserve encoded ordering of attributes. This is necessary for checking
    // the MAC value for the message
    public final LinkedHashMap<Integer, EapSimAttribute> attributeMap;

    private EapSimTypeData(int eapSubType, LinkedHashMap<Integer, EapSimAttribute> attributeMap) {
        this.eapSubtype = eapSubType;
        this.attributeMap = attributeMap;
    }

    /**
     * Decodes the given byte-array into an EapSimTypeData instance.
     *
     * @param typeData the byte-encoding of the EapSimTypeData to be parsed
     * @return an EapSimTypeData instance representing the data stored in typeData
     * @throws EapSimInvalidTypeDataException when typeData contains invalid EAP Subtypes, invalid
     *         Attributes, or the given typeData doesn't contain a full EapSimTypeData
     */
    public static EapSimTypeData decode(@NonNull byte[] typeData) throws
            EapSimInvalidTypeDataException {
        if (typeData == null) {
            throw new IllegalArgumentException("typeData must be non-null");
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(typeData);

        try {
            int eapSubType = Byte.toUnsignedInt(byteBuffer.get());
            if (!SUPPORTED_SUBTYPES.contains(eapSubType)) {
                throw new EapSimInvalidTypeDataException("Invalid EAP Type-Data");
            }

            // next two bytes are reserved (RFC 4186 Section 8.1)
            byteBuffer.getShort();

            // read attributes
            LinkedHashMap<Integer, EapSimAttribute> attributeMap = new LinkedHashMap<>();
            while (byteBuffer.hasRemaining()) {
                EapSimAttribute attribute = EapSimAttributeFactory.getInstance()
                        .getEapSimAttribute(byteBuffer);
                if (attribute instanceof EapSimUnsupportedAttribute) {
                    Log.d(TAG, "Unsupported EAP-SIM attribute during decoding: "
                            + attribute.attributeType);
                }
                attributeMap.put(attribute.attributeType, attribute);
            }
            return new EapSimTypeData(eapSubType, attributeMap);
        } catch (EapSimInvalidAttributeException ex) {
            throw new EapSimInvalidTypeDataException("Incorrectly formatted attribute", ex);
        } catch (EapSimUnsupportedAttributeException ex) {
            throw new EapSimInvalidTypeDataException("Invalid EAP-SIM Type-Data", ex);
        } catch (BufferUnderflowException ex) {
            throw new EapSimInvalidTypeDataException(
                    "Error reading EapSimTypeData from ByteBuffer", ex);
        }
    }
}
