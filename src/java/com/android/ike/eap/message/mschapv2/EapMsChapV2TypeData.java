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

package com.android.ike.eap.message.mschapv2;

import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.exceptions.mschapv2.EapMsChapV2ParsingException;
import com.android.ike.eap.message.EapMessage;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * EapMsChapV2TypeData represents the Type Data for an {@link EapMessage} during an EAP MSCHAPv2
 * session.
 */
public class EapMsChapV2TypeData {
    // EAP MSCHAPv2 OpCode values (EAP MSCHAPv2#2)
    public static final int EAP_MSCHAP_V2_CHALLENGE = 1;
    public static final int EAP_MSCHAP_V2_RESPONSE = 2;
    public static final int EAP_MSCHAP_V2_SUCCESS = 3;
    public static final int EAP_MSCHAP_V2_FAILURE = 4;
    public static final int EAP_MSCHAP_V2_CHANGE_PASSWORD = 7;

    public static final Map<Integer, String> EAP_OP_CODE_STRING = new HashMap<>();
    static {
        EAP_OP_CODE_STRING.put(EAP_MSCHAP_V2_CHALLENGE, "Challenge");
        EAP_OP_CODE_STRING.put(EAP_MSCHAP_V2_RESPONSE, "Response");
        EAP_OP_CODE_STRING.put(EAP_MSCHAP_V2_SUCCESS, "Success");
        EAP_OP_CODE_STRING.put(EAP_MSCHAP_V2_FAILURE, "Failure");
        EAP_OP_CODE_STRING.put(EAP_MSCHAP_V2_CHANGE_PASSWORD, "Change-Password");
    }

    private static final Set<Integer> SUPPORTED_OP_CODES = new HashSet<>();
    static {
        SUPPORTED_OP_CODES.add(EAP_MSCHAP_V2_CHALLENGE);
        SUPPORTED_OP_CODES.add(EAP_MSCHAP_V2_RESPONSE);
        SUPPORTED_OP_CODES.add(EAP_MSCHAP_V2_SUCCESS);
        SUPPORTED_OP_CODES.add(EAP_MSCHAP_V2_FAILURE);
    }

    public final int opCode;

    EapMsChapV2TypeData(int opCode) throws EapMsChapV2ParsingException {
        this.opCode = opCode;

        if (!SUPPORTED_OP_CODES.contains(opCode)) {
            throw new EapMsChapV2ParsingException("Unsupported opCode provided: " + opCode);
        }
    }

    /**
     * Encodes this EapMsChapV2TypeData instance as a byte[].
     *
     * @return byte[] representing the encoded value of this EapMsChapV2TypeData instance.
     */
    public byte[] encode() {
        throw new UnsupportedOperationException(
                "encode() not supported by " + this.getClass().getSimpleName());
    }

    abstract static class EapMsChapV2VariableTypeData extends EapMsChapV2TypeData {
        public final int msChapV2Id;
        public final int msLength;

        EapMsChapV2VariableTypeData(int opCode, int msChapV2Id, int msLength)
                throws EapMsChapV2ParsingException {
            super(opCode);

            this.msChapV2Id = msChapV2Id;
            this.msLength = msLength;
        }
    }

    /** Class for decoding EAP MSCHAPv2 type data. */
    public static class EapMsChapV2TypeDataDecoder {
        /**
         * DecodeResult represents the result from calling a decode method within
         * EapMsChapV2TypeDataDecoder. It will contain either an EapMsChapV2TypeData or an EapError.
         *
         * @param <T> The EapMsChapV2TypeData type that is wrapped in this DecodeResult
         */
        public static class DecodeResult<T extends EapMsChapV2TypeData> {
            public final T eapTypeData;
            public final EapError eapError;

            public DecodeResult(T eapTypeData) {
                this.eapTypeData = eapTypeData;
                this.eapError = null;
            }

            public DecodeResult(EapError eapError) {
                this.eapTypeData = null;
                this.eapError = eapError;
            }

            /**
             * Checks whether this instance represents a successful decode operation.
             *
             * @return true iff this DecodeResult represents a successfully decoded Type Data
             */
            public boolean isSuccessfulDecode() {
                return eapTypeData != null;
            }
        }
    }
}
