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

import static com.android.ike.eap.EapAuthenticator.LOG;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_ATTRIBUTE_STRING;

import android.annotation.NonNull;

import com.android.ike.eap.exceptions.simaka.EapSimAkaInvalidAttributeException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaUnsupportedAttributeException;
import com.android.ike.eap.exceptions.simaka.EapSimInvalidAtRandException;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.EapSimAkaUnsupportedAttribute;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * EapSimTypeData represents the Type Data for an {@link EapMessage} during an EAP-SIM session.
 */
public class EapSimTypeData {
    private static final String TAG = EapSimTypeData.class.getSimpleName();
    private static final int MIN_LEN_BYTES = 3; // subtype (1B) + reserved bytes (2B)

    // EAP-SIM Subtype values defined by IANA
    // https://www.iana.org/assignments/eapsimaka-numbers/eapsimaka-numbers.xhtml
    public static final int EAP_SIM_START = 10;
    public static final int EAP_SIM_CHALLENGE = 11;
    public static final int EAP_SIM_NOTIFICATION = 12;
    public static final int EAP_SIM_REAUTHENTICATION = 13;
    public static final int EAP_SIM_CLIENT_ERROR = 14;

    public static final Map<Integer, String> EAP_SIM_SUBTYPE_STRING = new HashMap<>();
    static {
        EAP_SIM_SUBTYPE_STRING.put(EAP_SIM_START, "Start");
        EAP_SIM_SUBTYPE_STRING.put(EAP_SIM_CHALLENGE, "Challenge");
        EAP_SIM_SUBTYPE_STRING.put(EAP_SIM_NOTIFICATION, "Notification");
        EAP_SIM_SUBTYPE_STRING.put(EAP_SIM_REAUTHENTICATION, "Re-authentication");
        EAP_SIM_SUBTYPE_STRING.put(EAP_SIM_CLIENT_ERROR, "Client-Error");
    }

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
    public final LinkedHashMap<Integer, EapSimAkaAttribute> attributeMap;

    @VisibleForTesting
    public EapSimTypeData(int eapSubType, LinkedHashMap<Integer, EapSimAkaAttribute> attributeMap) {
        this.eapSubtype = eapSubType;
        this.attributeMap = attributeMap;
    }

    public EapSimTypeData(int eapSubtype, List<EapSimAkaAttribute> attributes) {
        this.eapSubtype = eapSubtype;
        attributeMap = new LinkedHashMap<>();
        for (EapSimAkaAttribute attribute : attributes) {
            // TODO(b/135637161): check for duplicate attributes
            attributeMap.put(attribute.attributeType, attribute);
        }
    }

    /**
     * Creates and returns the byte-array encoding of this EapSimTypeData instance.
     *
     * @return byte[] representing the byte-encoding of this EapSimTypeData instance.
     */
    public byte[] encode() {
        int lengthInBytes = MIN_LEN_BYTES;
        for (EapSimAkaAttribute attribute : attributeMap.values()) {
            lengthInBytes += attribute.lengthInBytes;
        }

        ByteBuffer output = ByteBuffer.allocate(lengthInBytes);
        output.put((byte) eapSubtype);

        // two reserved bytes (RFC 4186 Section 8.1)
        output.put(new byte[2]);

        for (EapSimAkaAttribute attribute : attributeMap.values()) {
            attribute.encode(output);
        }

        return output.array();
    }

    /**
     * EapSimTypeDataDecoder will be used for decoding {@link EapSimTypeData} objects.
     */
    public static class EapSimTypeDataDecoder {
        /**
         * Decodes the given byte-array into a DecodeResult object.
         *
         * @param typeData the byte-encoding of the EapSimTypeData to be parsed
         * @return a DecodeResult object. If the decoding is successful, this will encapsulate an
         *         EapSimTypeData instance representing the data stored in typeData. Otherwise, it
         *         will contain the relevant AtClientErrorCode for the decoding error.
         */
        public DecodeResult decode(@NonNull byte[] typeData) {
            if (typeData == null) {
                LOG.d(TAG, "Invalid EAP Type-Data");
                return new DecodeResult(AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            ByteBuffer byteBuffer = ByteBuffer.wrap(typeData);
            try {
                int eapSubType = Byte.toUnsignedInt(byteBuffer.get());
                if (!SUPPORTED_SUBTYPES.contains(eapSubType)) {
                    LOG.d(TAG, "Invalid EAP Type-Data");
                    return new DecodeResult(AtClientErrorCode.UNABLE_TO_PROCESS);
                }

                // next two bytes are reserved (RFC 4186 Section 8.1)
                byteBuffer.get(new byte[2]);

                // read attributes
                LinkedHashMap<Integer, EapSimAkaAttribute> attributeMap = new LinkedHashMap<>();
                while (byteBuffer.hasRemaining()) {
                    EapSimAkaAttribute attribute = EapSimAttributeFactory.getInstance()
                            .getEapSimAttribute(byteBuffer);

                    if (attributeMap.containsKey(attribute.attributeType)) {
                        // Duplicate attributes are not allowed (RFC 4186#6.3.1)
                        LOG.e(TAG, "Duplicate attribute in parsed EAP-Message");
                        return new DecodeResult(AtClientErrorCode.UNABLE_TO_PROCESS);
                    }

                    if (attribute instanceof EapSimAkaUnsupportedAttribute) {
                        LOG.d(TAG, "Unsupported EAP-SIM attribute during decoding: "
                                + attribute.attributeType);
                    }
                    attributeMap.put(attribute.attributeType, attribute);
                }

                EapSimTypeData eapSimTypeData = new EapSimTypeData(eapSubType, attributeMap);
                logDecodedEapSimTypeData(eapSimTypeData);

                return new DecodeResult(eapSimTypeData);
            } catch (EapSimInvalidAtRandException ex) {
                LOG.e(TAG, "Invalid AtRand attribute", ex);
                return new DecodeResult(AtClientErrorCode.INSUFFICIENT_CHALLENGES);
            } catch (EapSimAkaInvalidAttributeException | BufferUnderflowException ex) {
                LOG.e(TAG, "Incorrectly formatted attribute", ex);
                return new DecodeResult(AtClientErrorCode.UNABLE_TO_PROCESS);
            } catch (EapSimAkaUnsupportedAttributeException ex) {
                LOG.e(TAG, "Unrecognized, non-skippable attribute encountered", ex);
                return new DecodeResult(AtClientErrorCode.UNABLE_TO_PROCESS);
            }
        }

        private void logDecodedEapSimTypeData(EapSimTypeData eapSimTypeData) {
            StringBuilder msg = new StringBuilder();
            msg.append("Decoded EAP-SIM type data: ");
            msg.append(EAP_SIM_SUBTYPE_STRING.getOrDefault(eapSimTypeData.eapSubtype, "UNKNOWN"));
            msg.append(" attributes=[ ");
            for (int attributeType : eapSimTypeData.attributeMap.keySet()) {
                msg.append(
                        EAP_ATTRIBUTE_STRING.getOrDefault(attributeType, "" + attributeType));
                msg.append(" ");
            }
            msg.append("]");
            LOG.i(TAG, msg.toString());
        }

        /**
         * DecodeResult represents the result from calling EapSimTypeDataDecoder.decode(). It will
         * contain either a decoded EapSimTypeData or the relevant AtClientErrorCode.
         */
        public static class DecodeResult {
            public final EapSimTypeData eapSimTypeData;
            public final AtClientErrorCode atClientErrorCode;

            public DecodeResult(EapSimTypeData eapSimTypeData) {
                this.eapSimTypeData = eapSimTypeData;
                this.atClientErrorCode = null;
            }

            public DecodeResult(AtClientErrorCode atClientErrorCode) {
                this.atClientErrorCode = atClientErrorCode;
                eapSimTypeData = null;
            }

            public boolean isSuccessfulDecode() {
                return eapSimTypeData != null;
            }
        }
    }
}
