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
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
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
    private static final int CONFIG_HEADER_LEN = 4;

    // TODO: Move these constant definitions to API
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
        CONFIG_ATTR_INTERNAL_IP4_ADDRESS,
        CONFIG_ATTR_INTERNAL_IP4_NETMASK,
        CONFIG_ATTR_INTERNAL_IP4_DNS,
        CONFIG_ATTR_INTERNAL_IP4_NBNS,
        CONFIG_ATTR_INTERNAL_IP4_DHCP,
        CONFIG_ATTR_APPLICATION_VERSION,
        CONFIG_ATTR_INTERNAL_IP6_ADDRESS,
        CONFIG_ATTR_INTERNAL_IP6_DNS,
        CONFIG_ATTR_INTERNAL_IP6_DHCP,
        CONFIG_ATTR_INTERNAL_IP4_SUBNET,
        CONFIG_ATTR_SUPPORTED_ATTRIBUTES,
        CONFIG_ATTR_INTERNAL_IP6_SUBNET
    })
    public @interface ConfigAttr {}

    public static final int CONFIG_ATTR_INTERNAL_IP4_ADDRESS = 1;
    public static final int CONFIG_ATTR_INTERNAL_IP4_NETMASK = 2;
    public static final int CONFIG_ATTR_INTERNAL_IP4_DNS = 3;
    public static final int CONFIG_ATTR_INTERNAL_IP4_NBNS = 4;
    public static final int CONFIG_ATTR_INTERNAL_IP4_DHCP = 6;
    public static final int CONFIG_ATTR_APPLICATION_VERSION = 7;
    public static final int CONFIG_ATTR_INTERNAL_IP6_ADDRESS = 8;
    public static final int CONFIG_ATTR_INTERNAL_IP6_DNS = 10;
    public static final int CONFIG_ATTR_INTERNAL_IP6_DHCP = 12;
    public static final int CONFIG_ATTR_INTERNAL_IP4_SUBNET = 13;
    public static final int CONFIG_ATTR_SUPPORTED_ATTRIBUTES = 14;
    public static final int CONFIG_ATTR_INTERNAL_IP6_SUBNET = 15;

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
        private static final int ATTRIBUTE_TYPE_MASK = 0x7fff;

        private static final int ATTRIBUTE_HEADER_LEN = 4;

        protected static final int VALUE_LEN_NOT_INCLUDED = 0;
        protected static final int IPV4_ADDRESS_LEN = 4;
        protected static final int IPV6_ADDRESS_LEN = 16;

        public final int attributeType;

        protected ConfigAttribute(int attributeType) {
            this.attributeType = attributeType;
        }

        protected ConfigAttribute(int attributeType, int len) throws InvalidSyntaxException {
            this(attributeType);

            if (!isLengthValid(len)) {
                throw new InvalidSyntaxException("Invalid configuration length");
            }
        }

        /**
         * Package private method to decode ConfigAttribute list from an inbound packet
         *
         * <p>NegativeArraySizeException and BufferUnderflowException will be caught in {@link
         * IkeMessage}
         */
        static List<ConfigAttribute> decodeAttributeFrom(ByteBuffer inputBuffer)
                throws InvalidSyntaxException {
            List<ConfigAttribute> configList = new LinkedList();

            while (inputBuffer.hasRemaining()) {
                int attributeType = Short.toUnsignedInt(inputBuffer.getShort());
                int length = Short.toUnsignedInt(inputBuffer.getShort());
                byte[] value = new byte[length];
                inputBuffer.get(value);

                switch (attributeType) {
                    case CONFIG_ATTR_INTERNAL_IP4_ADDRESS:
                        configList.add(new ConfigAttributeIpv4Address(value));
                        break;
                    default:
                        // Ignore unrecognized attribute type.
                }
            }

            return configList;
        }

        /** Encode attribute to ByteBuffer. */
        public void encodeAttributeToByteBuffer(ByteBuffer buffer) {
            buffer.putShort((short) (attributeType & ATTRIBUTE_TYPE_MASK))
                    .putShort((short) getValueLength());
            encodeValueToByteBuffer(buffer);
        }

        /** Get attribute length. */
        public int getAttributeLen() {
            return ATTRIBUTE_HEADER_LEN + getValueLength();
        }

        protected abstract void encodeValueToByteBuffer(ByteBuffer buffer);

        protected abstract int getValueLength();

        protected abstract boolean isLengthValid(int length);
    }

    /**
     * This class represents common information of all Configuration Attributes whoses value is one
     * IPv4 address or empty.
     */
    abstract static class ConfigAttrIpv4AddressBase extends ConfigAttribute {
        public final Inet4Address address;

        protected ConfigAttrIpv4AddressBase(int attributeType, Inet4Address address) {
            super(attributeType);
            this.address = address;
        }

        protected ConfigAttrIpv4AddressBase(int attributeType) {
            super(attributeType);
            this.address = null;
        }

        protected ConfigAttrIpv4AddressBase(int attributeType, byte[] value)
                throws InvalidSyntaxException {
            super(attributeType, value.length);

            if (value.length == VALUE_LEN_NOT_INCLUDED) {
                address = null;
                return;
            }

            try {
                address = (Inet4Address) Inet4Address.getByAddress(value);
            } catch (UnknownHostException e) {
                throw new InvalidSyntaxException("Invalid attribute value", e);
            }
        }

        @Override
        protected void encodeValueToByteBuffer(ByteBuffer buffer) {
            if (address == null) {
                buffer.put(new byte[0]);
                return;
            }

            buffer.put(address.getAddress());
        }

        @Override
        protected int getValueLength() {
            return address == null ? 0 : IPV4_ADDRESS_LEN;
        }

        @Override
        protected boolean isLengthValid(int length) {
            return length == IPV4_ADDRESS_LEN || length == VALUE_LEN_NOT_INCLUDED;
        }
    }

    /** This class represents Configuration Attribute for IPv4 internal address. */
    public static class ConfigAttributeIpv4Address extends ConfigAttrIpv4AddressBase {
        /** Construct an instance with specified address for an outbound packet. */
        public ConfigAttributeIpv4Address(Inet4Address ipv4Address) {
            super(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, ipv4Address);
        }

        /**
         * Construct an instance without a specified address for an outbound packet.
         *
         * <p>It should be only used in a configuration request.
         */
        public ConfigAttributeIpv4Address() {
            super(CONFIG_ATTR_INTERNAL_IP4_ADDRESS);
        }

        /** Construct an instance with a decoded inbound packet. */
        public ConfigAttributeIpv4Address(byte[] value) throws InvalidSyntaxException {
            super(CONFIG_ATTR_INTERNAL_IP4_ADDRESS, value);
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
        encodePayloadHeaderToByteBuffer(nextPayload, getPayloadLength(), byteBuffer);
        byteBuffer.put((byte) configType).put(new byte[CONFIG_HEADER_RESERVED_LEN]);

        for (ConfigAttribute attr : recognizedAttributeList) {
            attr.encodeAttributeToByteBuffer(byteBuffer);
        }
    }

    /**
     * Get entire payload length.
     *
     * @return entire payload length.
     */
    @Override
    protected int getPayloadLength() {
        int len = GENERIC_HEADER_LENGTH + CONFIG_HEADER_LEN;

        for (ConfigAttribute attr : recognizedAttributeList) {
            len += attr.getAttributeLen();
        }

        return len;
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
