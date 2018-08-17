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

import android.util.Pair;

import com.android.ike.ikev2.IkeDhParams;
import com.android.ike.ikev2.exceptions.IkeException;
import com.android.ike.ikev2.exceptions.InvalidSyntaxException;
import com.android.ike.ikev2.utils.BigIntegerUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * IkeKePayload represents a Key Exchange payload
 *
 * <p>This class provides methods for generating Diffie-Hellman value and doing Diffie-Hellman
 * exhchange. Upper layer should ignore IkeKePayload with unsupported DH group type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#page-89">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2).
 */
public final class IkeKePayload extends IkePayload {
    private static final int KE_HEADER_LEN = 4;

    // Key exchange data length in octets
    private static final int DH_GROUP_1024_BIT_MODP_DATA_LEN = 128;
    private static final int DH_GROUP_2048_BIT_MODP_DATA_LEN = 256;

    // Algorithm name of Diffie-Hellman
    private static final String KEY_EXCHANGE_ALGORITHM = "DH";

    // TODO: Create a library initializer that checks if Provider supports DH algorithm.

    /** Supported dhGroup falls into {@link DhGroup} */
    public final int dhGroup;

    public final byte[] keyExchangeData;

    /**
     * Construct an instance of IkeKePayload in the context of IkePayloadFactory
     *
     * @param critical indicates if this payload is critical. Ignored in supported payload as
     *     instructed by the RFC 7296.
     * @param payloadBody payload body in byte array
     * @throws IkeException if there is any error
     * @see <a href="https://tools.ietf.org/html/rfc7296#page-76">RFC 7296, Internet Key Exchange
     *     Protocol Version 2 (IKEv2), Critical.
     */
    IkeKePayload(boolean critical, byte[] payloadBody) throws IkeException {
        super(PAYLOAD_TYPE_KE, critical);
        ByteBuffer inputBuffer = ByteBuffer.wrap(payloadBody);
        dhGroup = Short.toUnsignedInt(inputBuffer.getShort());
        // Skip reserved field
        inputBuffer.getShort();

        int dataSize = payloadBody.length - KE_HEADER_LEN;
        // Check if dataSize matches the DH group type
        boolean isValidSyntax = true;
        switch (dhGroup) {
            case DH_GROUP_1024_BIT_MODP:
                isValidSyntax = DH_GROUP_1024_BIT_MODP_DATA_LEN == dataSize;
                break;
            case DH_GROUP_2048_BIT_MODP:
                isValidSyntax = DH_GROUP_2048_BIT_MODP_DATA_LEN == dataSize;
                break;
            default:
                // For unsupported DH group, we cannot check its syntax. Upper layer will ingore
                // this payload.
        }
        if (!isValidSyntax) {
            throw new InvalidSyntaxException("Invalid KE payload length for provided DH group.");
        }

        keyExchangeData = new byte[dataSize];
        inputBuffer.get(keyExchangeData);
    }

    /**
     * Construct an instance of IkeKePayload for building an outbound packet.
     *
     * <p>Critical bit in this payload must not be set as instructed in RFC 7296.
     *
     * @param dh DH group for this KE payload
     * @param keData the Key Exchange data
     * @see <a href="https://tools.ietf.org/html/rfc7296#page-76">RFC 7296, Internet Key Exchange
     *     Protocol Version 2 (IKEv2), Critical.
     */
    private IkeKePayload(@DhGroup int dh, byte[] keData) {
        super(PAYLOAD_TYPE_KE, false);
        dhGroup = dh;
        keyExchangeData = keData;
    }

    /**
     * Encode KE payload to ByteBuffer.
     *
     * @param nextPayload type of payload that follows this payload.
     * @param byteBuffer destination ByteBuffer that stores encoded payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        throw new UnsupportedOperationException(
                "It is not supported to encode a " + getTypeString());
        // TODO: Implement encoding KE payload.
    }

    /**
     * Get entire payload length.
     *
     * @return entire payload length.
     */
    @Override
    protected int getPayloadLength() {
        throw new UnsupportedOperationException(
                "It is not supported to get payload length of " + getTypeString());
        // TODO: Implement this method for KE payload.
    }

    /**
     * Construct an instance of IkeKePayload according to its {@link DhGroup}.
     *
     * @param dh the Dh-Group. It should be in {@link DhGroup}
     * @return Pair of generated private key and an instance of IkeKePayload with key exchange data.
     * @throws GeneralSecurityException for security-related exception.
     */
    public static Pair<DHPrivateKeySpec, IkeKePayload> getKePayload(@DhGroup int dh)
            throws GeneralSecurityException {
        BigInteger baseGen = BigInteger.valueOf(IkeDhParams.BASE_GENERATOR_MODP);
        BigInteger prime = BigInteger.ZERO;
        int keySize = 0;
        switch (dh) {
            case DH_GROUP_1024_BIT_MODP:
                prime =
                        BigIntegerUtils.unsignedHexStringToBigInteger(
                                IkeDhParams.PRIME_1024_BIT_MODP);
                keySize = DH_GROUP_1024_BIT_MODP_DATA_LEN;
                break;
            case DH_GROUP_2048_BIT_MODP:
                prime =
                        BigIntegerUtils.unsignedHexStringToBigInteger(
                                IkeDhParams.PRIME_2048_BIT_MODP);
                keySize = DH_GROUP_2048_BIT_MODP_DATA_LEN;
                break;
            default:
                throw new IllegalArgumentException("DH group not supported: " + dh);
        }

        DHParameterSpec dhParams = new DHParameterSpec(prime, baseGen);

        KeyPairGenerator dhKeyPairGen =
                KeyPairGenerator.getInstance(
                        KEY_EXCHANGE_ALGORITHM, IkeMessage.getSecurityProvider());
        // By default SecureRandom uses AndroidOpenSSL provided SHA1PRNG Algorithm, which takes
        // /dev/urandom as seed source.
        dhKeyPairGen.initialize(dhParams, new SecureRandom());

        KeyPair keyPair = dhKeyPairGen.generateKeyPair();

        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
        DHPrivateKeySpec dhPrivateKeyspec = new DHPrivateKeySpec(privateKey.getX(), prime, baseGen);
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

        // Zero-pad the public key without the sign bit
        byte[] keData = BigIntegerUtils.bigIntegerToUnsignedByteArray(publicKey.getY(), keySize);

        return new Pair(dhPrivateKeyspec, new IkeKePayload(dh, keData));
    }

    /**
     * Calculate the shared secret.
     *
     * @param privateKeySpec contains the local private key, DH prime and DH base generator.
     * @param remotePublicKey the public key from remote server.
     * @throws GeneralSecurityException for security-related exception.
     */
    public static byte[] getSharedKey(DHPrivateKeySpec privateKeySpec, byte[] remotePublicKey)
            throws GeneralSecurityException {
        BigInteger publicKeyValue = BigIntegerUtils.unsignedByteArrayToBigInteger(remotePublicKey);
        BigInteger primeValue = privateKeySpec.getP();
        // TODO: Add recipient test of remotePublicKey, as instructed by RFC6989 section 2.1

        BigInteger baseGenValue = privateKeySpec.getG();

        DHPublicKeySpec publicKeySpec =
                new DHPublicKeySpec(publicKeyValue, primeValue, baseGenValue);
        KeyFactory dhKeyFactory =
                KeyFactory.getInstance(KEY_EXCHANGE_ALGORITHM, IkeMessage.getSecurityProvider());
        DHPublicKey publicKey = (DHPublicKey) dhKeyFactory.generatePublic(publicKeySpec);
        DHPrivateKey privateKey = (DHPrivateKey) dhKeyFactory.generatePrivate(privateKeySpec);

        // Calculate shared secret
        KeyAgreement dhKeyAgreement =
                KeyAgreement.getInstance(KEY_EXCHANGE_ALGORITHM, IkeMessage.getSecurityProvider());
        dhKeyAgreement.init(privateKey);
        dhKeyAgreement.doPhase(publicKey, true/** Last phase */);

        return dhKeyAgreement.generateSecret();
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        return "KE Payload";
    }
}
