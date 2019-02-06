/*
 * Copyright (C) 2018 The Android Open Source Project
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

package com.android.ike.ikev2.message;

import android.annotation.IntDef;

import com.android.ike.ikev2.exceptions.IkeException;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;

/**
 * IkeCertPayload represents a Certification Payload.
 *
 * <p>Certification Payload is only sent in IKE_AUTH exchange. When sending multiple certificates,
 * IKE library should put certificates in order starting with the target certificate and ending with
 * a certificate issued by the trust anchor. While when receiving an inbound packet, IKE library
 * should take first certificate as the target certificate but treat the rest unordered.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.6">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeCertPayload extends IkePayload {

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        CERTIFICATE_ENCODING_X509_CERT_SIGNATURE,
        CERTIFICATE_ENCODING_CRL,
        CERTIFICATE_ENCODING_X509_CERT_HASH_URL,
        CERTIFICATE_ENCODING_X509_CERT_BUNDLE_HAS_URL
    })
    public @interface CertificateEncoding {}

    public static final int CERTIFICATE_ENCODING_X509_CERT_SIGNATURE = 4;
    public static final int CERTIFICATE_ENCODING_CRL = 7;
    public static final int CERTIFICATE_ENCODING_X509_CERT_HASH_URL = 12;
    public static final int CERTIFICATE_ENCODING_X509_CERT_BUNDLE_HAS_URL = 13;

    IkeCertPayload(boolean critical, byte[] payloadBody) throws IkeException {
        super(PAYLOAD_TYPE_CERT, critical);
        // TODO: Decode and validate syntax of payloadBody.
    }

    /**
     * Encode Certification Payload to ByteBuffer.
     *
     * @param nextPayload type of payload that follows this payload.
     * @param byteBuffer destination ByteBuffer that stores encoded payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        // TODO: Implement it.
        throw new UnsupportedOperationException(
                "It is not supported to encode a " + getTypeString());
    }

    /**
     * Get entire payload length.
     *
     * @return entire payload length.
     */
    @Override
    protected int getPayloadLength() {
        // TODO: Implement it.
        throw new UnsupportedOperationException(
                "It is not supported to get payload length of " + getTypeString());
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        return "Certification Payload";
    }
}
