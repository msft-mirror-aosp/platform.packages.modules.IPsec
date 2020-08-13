/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.internal.net.eap.message.ttls;

import static com.android.internal.net.eap.EapAuthenticator.LOG;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.net.eap.EapResult.EapError;
import com.android.internal.net.eap.exceptions.ttls.EapTtlsParsingException;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * EapTtlsAvp represents the structure of an AVP during an EAP-TTLS session (RFC5281#10.1) The
 * structure of the flag byte is as follows:
 *
 * <pre>
 * |---+---+---+---+---+-----------+
 * | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
 * | V | M | r | r | r | r | r | r |
 * |---+---+---+---+---+---+---+---+
 * V = Vendor ID present
 * M = AVP support is mandatory
 * r = Reserved bits (must be ignored)
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc5281#section-10.1">RFC 5281, Extensible
 *     Authentication Protocol Tunneled Transport Layer Security Authenticated Protocol Version 0
 *     (EAP-TTLSv0)</a>
 */
public class EapTtlsAvp {
    private static final String TAG = EapTtlsAvp.class.getSimpleName();

    // AVP code derived from RFC3579#3.1. Note that the EAP-TTLS uses an custom AVP structure (see
    // RFC 5281, section 10.1), as opposed to the one defined in RFC 3579.
    private static final int EAP_MESSAGE_AVP_CODE = 79;

    private static final int AVP_CODE_LEN_BYTES = 4;
    private static final int AVP_FLAGS_LEN_BYTES = 1;
    private static final int AVP_LENGTH_LEN_BYTES = 3;
    private static final int AVP_VENDOR_ID_LEN_BYTES = 4;
    private static final int AVP_HEADER_LEN_BYTES =
            AVP_CODE_LEN_BYTES + AVP_FLAGS_LEN_BYTES + AVP_LENGTH_LEN_BYTES;
    private static final int AVP_BYTE_ALIGNMENT = 4;

    private static final int FLAG_VENDOR_ID_INCLUDED = 1 << 7;
    private static final int FLAG_AVP_MANDATORY = 1 << 6;

    public final int avpCode;
    public final int avpLength;
    public final int vendorId;
    public final byte[] data;

    public final boolean isMandatory;
    public final boolean isVendorIdPresent;

    @VisibleForTesting
    EapTtlsAvp(ByteBuffer buffer) throws EapTtlsParsingException {
        avpCode = buffer.getInt();
        byte avpFlags = buffer.get();

        isMandatory = (avpFlags & FLAG_AVP_MANDATORY) != 0;
        isVendorIdPresent = (avpFlags & FLAG_VENDOR_ID_INCLUDED) != 0;

        avpLength = getAvpLength(buffer);
        int dataLength = avpLength - AVP_HEADER_LEN_BYTES;

        if (isVendorIdPresent) {
            dataLength -= AVP_VENDOR_ID_LEN_BYTES;
            vendorId = buffer.getInt();
        } else {
            // no vendor ID is equivalent to a vendor ID of 0 (RFC5281#10.1)
            vendorId = 0;
        }

        if (dataLength < 0) {
            throw new EapTtlsParsingException(
                    "Received an AVP with an invalid length: "
                            + avpLength
                            + ". Data length was predicted to be "
                            + dataLength);
        }

        data = new byte[dataLength];
        buffer.get(data);

        // the remaining padding is consumed in order to align with the next AVP header
        int paddingSize = getAvpPadding(avpLength);
        buffer.get(new byte[paddingSize]);
    }

    /**
     * Retrieves the required padding bytes (4 byte aligned) for a given length
     *
     * @param avpLength the length to pad
     * @return the required padding bytes
     */
    @VisibleForTesting
    static int getAvpPadding(int avpLength) {
        if (avpLength % AVP_BYTE_ALIGNMENT == 0) {
            return 0;
        }
        return AVP_BYTE_ALIGNMENT - (avpLength % AVP_BYTE_ALIGNMENT);
    }

    /**
     * Converts a byte array of size 3 to its integer representation
     *
     * <p>As per RFC5281#10.2, the AVP length field is 3 bytes
     *
     * @param buffer a byte buffer to extract the length from
     * @return an int representation of the byte array
     * @throws BufferUnderflowException if the buffer has less than 3 bytes remaining
     */
    @VisibleForTesting
    static int getAvpLength(ByteBuffer buffer) throws BufferUnderflowException {
        return (Byte.toUnsignedInt(buffer.get()) << 16)
                | (Byte.toUnsignedInt(buffer.get()) << 8)
                | Byte.toUnsignedInt(buffer.get());
    }

    /** EapTtlsAvpDecoder will be used for decoding {@link EapTtlsAvp} objects. */
    public static class EapTtlsAvpDecoder {

        /**
         * Decodes and returns an EapTtlsAvp for the specified EAP-TTLS AVP.
         *
         * <p>In the case that multiple AVPs are received, all AVPs will be decoded, but only the
         * EAP-MESSAGE AVP will be stored. All AVP codes and Vendor-IDs will be logged. Furthermore,
         * if multiple EAP-MESSAGE AVPs are received, this will be treated as an error.
         *
         * @param avp a byte array representing the AVP
         * @return DecodeResult wrapping an EapTtlsAvp instance for the given EapTtlsAvp iff the
         *     eapTtlsAvp is formatted correctly. Otherwise, the DecodeResult wraps the appropriate
         *     EapError.
         */
        public AvpDecodeResult decode(byte[] avp) {
            try {
                // AVPs must be 4 byte aligned (RFC5281#10.2)
                if (avp.length % AVP_BYTE_ALIGNMENT != 0) {
                    return new AvpDecodeResult(
                            new EapError(
                                    new EapTtlsParsingException(
                                            "Received one or more invalid AVPs: AVPs must be 4"
                                                    + " byte aligned.")));
                }
                ByteBuffer avpBuffer = ByteBuffer.wrap(avp);
                EapTtlsAvp eapMessageAvp = null;

                while (avpBuffer.hasRemaining()) {
                    EapTtlsAvp decodedAvp = new EapTtlsAvp(avpBuffer);
                    LOG.i(
                            TAG,
                            "Decoded AVP with code "
                                    + decodedAvp.avpCode
                                    + " and vendor ID "
                                    + decodedAvp.vendorId);

                    if (decodedAvp.avpCode == EAP_MESSAGE_AVP_CODE) {
                        if (eapMessageAvp != null) {
                            // Only one EAP-MESSAGE AVP is expected at a time
                            return new AvpDecodeResult(
                                    new EapError(
                                            new EapTtlsParsingException(
                                                    "Received multiple EAP-MESSAGE AVPs in one"
                                                            + " message")));
                        }
                        eapMessageAvp = decodedAvp;
                    } else if (decodedAvp.isMandatory) {
                        // As per RFC5281#10.1, if an AVP tagged as mandatory is unsupported, the
                        // negotiation should fail
                        return new AvpDecodeResult(
                                new EapError(
                                        new EapTtlsParsingException(
                                                "Received an AVP that requires support for AVP code"
                                                        + decodedAvp.avpCode)));
                    }
                }

                if (eapMessageAvp == null) {
                    return new AvpDecodeResult(
                            new EapError(
                                    new EapTtlsParsingException(
                                            "No EAP-MESSAGE (79) AVP was found")));
                }

                return new AvpDecodeResult(eapMessageAvp);
            } catch (BufferUnderflowException | EapTtlsParsingException e) {
                return new AvpDecodeResult(new EapError(e));
            }
        }

        /**
         * DecodeResult represents the result from attempting to decode a sequence of EAP-TTLS
         * AVPs. It will contain either an EapTtlsAvp or an EapError.
         *
         * <p>In the case that multiple AVPs are received, all AVPs will be decoded and their AVP
         * codes/Vendor-ID will be logged. However, only the EAP-MESSAGE AVP will be stored in the
         * decode result. Furthermore, if zero, or multiple EAP-MESSAGE AVPs are received, this will
         * be treated as an error.
         */
        public static class AvpDecodeResult {
            public final EapTtlsAvp eapTtlsAvp;
            public final EapError eapError;

            public AvpDecodeResult(EapTtlsAvp eapTtlsAvp) {
                this.eapTtlsAvp = eapTtlsAvp;
                this.eapError = null;
            }

            public AvpDecodeResult(EapError eapError) {
                this.eapTtlsAvp = null;
                this.eapError = eapError;
            }

            /**
             * Checks whether this instance represents a successful decode operation.
             *
             * @return true iff this DecodeResult represents a successfully decoded Type Data
             */
            public boolean isSuccessfulDecode() {
                return eapTtlsAvp != null;
            }
        }
    }
}
