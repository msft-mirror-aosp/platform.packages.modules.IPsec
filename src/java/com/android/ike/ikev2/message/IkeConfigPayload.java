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

package com.android.ike.ikev2.message;

import android.annotation.IntDef;

import com.android.ike.ikev2.exceptions.InvalidSyntaxException;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * This class represents Configuration payload.
 *
 * <p>Configuration payload is used to exchange configuration information between IKE peers.
 *
 * <p>Configuration type should be consistent with the IKE message direction (e.g. a request Config
 * Payload should be in a request IKE message). IKE library will ignore Config Payload with
 * inconsistent type or with unrecognized type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#section-3.6">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public final class IkeConfigPayload extends IkePayload {
    private static final int CONFIG_HEADER_RESERVED_LEN = 3;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({CONFIG_TYPE_REQUEST, CONFIG_TYPE_REPLY})
    public @interface ConfigType {}

    // We don't support CONFIG_TYPE_SET and CONFIG_TYPE_ACK
    public static final int CONFIG_TYPE_REQUEST = 1;
    public static final int CONFIG_TYPE_REPLY = 2;

    @ConfigType public final int configType;
    public final List<ConfigAttribute> recognizedAttributeList;

    /** Build an IkeConfigPayload from a decoded inbound IKE packet. */
    IkeConfigPayload(boolean critical, byte[] payloadBody) throws InvalidSyntaxException {
        super(PAYLOAD_TYPE_CP, critical);

        ByteBuffer inputBuffer = ByteBuffer.wrap(payloadBody);
        configType = Byte.toUnsignedInt(inputBuffer.get());
        inputBuffer.get(new byte[CONFIG_HEADER_RESERVED_LEN]);

        recognizedAttributeList = ConfigAttribute.decodeAttributeFrom(inputBuffer);
    }

    /** Build an IkeConfigPayload instance for an outbound IKE packet. */
    public IkeConfigPayload(boolean isReply, List<ConfigAttribute> attributeList) {
        super(PAYLOAD_TYPE_CP, false);
        this.configType = isReply ? CONFIG_TYPE_REPLY : CONFIG_TYPE_REQUEST;
        this.recognizedAttributeList = attributeList;
    }

    // TODO: Create ConfigAttribute subclasses for each attribute.

    /** This class represents common information of all Configuration Attributes. */
    public abstract static class ConfigAttribute {
        /**
         * Package private method to decode ConfigAttribute list from an inbound packet
         *
         * <p>NegativeArraySizeException and BufferUnderflowException will be caught in {@link
         * IkeMessage}
         */
        static List<ConfigAttribute> decodeAttributeFrom(ByteBuffer inputBuffer)
                throws InvalidSyntaxException {
            // TODO: Implement it.
            return null;
        }
    }

    /**
     * Encode Configuration payload to ByteBUffer.
     *
     * @param nextPayload type of payload that follows this payload.
     * @param byteBuffer destination ByteBuffer that stores encoded payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        // TODO: Implement it.
        throw new UnsupportedOperationException();
    }

    /**
     * Get entire payload length.
     *
     * @return entire payload length.
     */
    @Override
    protected int getPayloadLength() {
        // TODO: Implement it.
        throw new UnsupportedOperationException();
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        return "Configuration Payload";
    }
}
