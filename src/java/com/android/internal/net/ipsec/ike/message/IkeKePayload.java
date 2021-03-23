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

package com.android.internal.net.ipsec.ike.message;

import static android.net.ipsec.ike.SaProposal.DH_GROUP_1024_BIT_MODP;
import static android.net.ipsec.ike.SaProposal.DH_GROUP_1536_BIT_MODP;
import static android.net.ipsec.ike.SaProposal.DH_GROUP_2048_BIT_MODP;
import static android.net.ipsec.ike.SaProposal.DH_GROUP_3072_BIT_MODP;
import static android.net.ipsec.ike.SaProposal.DH_GROUP_4096_BIT_MODP;

import static com.android.internal.net.utils.BigIntegerUtils.unsignedHexStringToBigInteger;

import android.annotation.Nullable;
import android.net.ipsec.ike.SaProposal;
import android.net.ipsec.ike.exceptions.IkeProtocolException;
import android.net.ipsec.ike.exceptions.InvalidSyntaxException;
import android.util.SparseArray;

import com.android.internal.net.ipsec.ike.IkeDhParams;
import com.android.internal.net.ipsec.ike.utils.RandomnessFactory;
import com.android.internal.net.utils.BigIntegerUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * IkeKePayload represents a Key Exchange payload
 *
 * <p>This class provides methods for generating Diffie-Hellman value and doing Diffie-Hellman
 * exhchange. Upper layer should ignore IkeKePayload with unsupported DH group type.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7296#page-89">RFC 7296, Internet Key Exchange
 *     Protocol Version 2 (IKEv2)</a>
 */
public final class IkeKePayload extends IkePayload {
    private static final int KE_HEADER_LEN = 4;
    private static final int KE_HEADER_RESERVED = 0;

    // Key exchange data length in octets
    private static final int DH_GROUP_1024_BIT_MODP_PUBLIC_KEY_LEN = 128;
    private static final int DH_GROUP_1536_BIT_MODP_PUBLIC_KEY_LEN = 192;
    private static final int DH_GROUP_2048_BIT_MODP_PUBLIC_KEY_LEN = 256;
    private static final int DH_GROUP_3072_BIT_MODP_PUBLIC_KEY_LEN = 384;
    private static final int DH_GROUP_4096_BIT_MODP_PUBLIC_KEY_LEN = 512;

    private static final SparseArray<Integer> PUBLIC_KEY_LEN_MAP = new SparseArray<>();

    static {
        PUBLIC_KEY_LEN_MAP.put(DH_GROUP_1024_BIT_MODP, DH_GROUP_1024_BIT_MODP_PUBLIC_KEY_LEN);
        PUBLIC_KEY_LEN_MAP.put(DH_GROUP_1536_BIT_MODP, DH_GROUP_1536_BIT_MODP_PUBLIC_KEY_LEN);
        PUBLIC_KEY_LEN_MAP.put(DH_GROUP_2048_BIT_MODP, DH_GROUP_2048_BIT_MODP_PUBLIC_KEY_LEN);
        PUBLIC_KEY_LEN_MAP.put(DH_GROUP_3072_BIT_MODP, DH_GROUP_3072_BIT_MODP_PUBLIC_KEY_LEN);
        PUBLIC_KEY_LEN_MAP.put(DH_GROUP_4096_BIT_MODP, DH_GROUP_4096_BIT_MODP_PUBLIC_KEY_LEN);
    }

    private static final SparseArray<BigInteger> MODP_PRIME_MAP = new SparseArray<>();

    static {
        MODP_PRIME_MAP.put(
                DH_GROUP_1024_BIT_MODP,
                unsignedHexStringToBigInteger(IkeDhParams.PRIME_1024_BIT_MODP));
        MODP_PRIME_MAP.put(
                DH_GROUP_1536_BIT_MODP,
                unsignedHexStringToBigInteger(IkeDhParams.PRIME_1536_BIT_MODP));
        MODP_PRIME_MAP.put(
                DH_GROUP_2048_BIT_MODP,
                unsignedHexStringToBigInteger(IkeDhParams.PRIME_2048_BIT_MODP));
        MODP_PRIME_MAP.put(
                DH_GROUP_3072_BIT_MODP,
                unsignedHexStringToBigInteger(IkeDhParams.PRIME_3072_BIT_MODP));
        MODP_PRIME_MAP.put(
                DH_GROUP_4096_BIT_MODP,
                unsignedHexStringToBigInteger(IkeDhParams.PRIME_4096_BIT_MODP));
    }

    // Algorithm name of Diffie-Hellman
    private static final String KEY_EXCHANGE_ALGORITHM = "DH";

    // TODO: Create a library initializer that checks if Provider supports DH algorithm.

    /** Supported dhGroup falls into {@link DhGroup} */
    public final int dhGroup;

    /** Public DH key for the recipient to calculate shared key. */
    public final byte[] keyExchangeData;

    /** Flag indicates if this is an outbound payload. */
    public final boolean isOutbound;

    /**
     * localPrivateKey caches the locally generated private key when building an outbound KE
     * payload. It will not be sent out. It is only used to calculate DH shared key when IKE library
     * receives a public key from the remote server.
     *
     * <p>localPrivateKey of a inbound payload will be set to null. Caller MUST ensure its an
     * outbound payload before using localPrivateKey.
     */
    @Nullable public final PrivateKey localPrivateKey;

    /**
     * Construct an instance of IkeKePayload in the context of IkePayloadFactory
     *
     * @param critical indicates if this payload is critical. Ignored in supported payload as
     *     instructed by the RFC 7296.
     * @param payloadBody payload body in byte array
     * @throws IkeProtocolException if there is any error
     * @see <a href="https://tools.ietf.org/html/rfc7296#page-76">RFC 7296, Internet Key Exchange
     *     Protocol Version 2 (IKEv2), Critical.
     */
    IkeKePayload(boolean critical, byte[] payloadBody) throws IkeProtocolException {
        super(PAYLOAD_TYPE_KE, critical);

        isOutbound = false;
        localPrivateKey = null;

        ByteBuffer inputBuffer = ByteBuffer.wrap(payloadBody);

        dhGroup = Short.toUnsignedInt(inputBuffer.getShort());
        if (!PUBLIC_KEY_LEN_MAP.contains(dhGroup)) {
            throw new IllegalArgumentException("Invalid DH group " + dhGroup);
        }

        // Skip reserved field
        inputBuffer.getShort();

        int dataSize = payloadBody.length - KE_HEADER_LEN;

        // Check if dataSize matches the DH group type
        if (dataSize != PUBLIC_KEY_LEN_MAP.get(dhGroup)) {
            throw new InvalidSyntaxException("Invalid KE payload length for provided DH group.");
        }

        keyExchangeData = new byte[dataSize];
        inputBuffer.get(keyExchangeData);
    }

    /** Constructor for building an outbound KE payload. */
    private IkeKePayload(int dhGroup, byte[] keyExchangeData, PrivateKey localPrivateKey) {
        super(PAYLOAD_TYPE_KE, true /* critical */);
        this.dhGroup = dhGroup;
        this.isOutbound = true;
        this.keyExchangeData = keyExchangeData;
        this.localPrivateKey = localPrivateKey;
    }

    /**
     * Construct an instance of IkeKePayload for building an outbound packet.
     *
     * <p>Generate a DH key pair. Cache the private key and send out the public key as
     * keyExchangeData.
     *
     * <p>Critical bit in this payload must not be set as instructed in RFC 7296.
     *
     * @param dh DH group for this KE payload
     * @param randomnessFactory the randomness factory
     * @see <a href="https://tools.ietf.org/html/rfc7296#page-76">RFC 7296, Internet Key Exchange
     *     Protocol Version 2 (IKEv2), Critical.
     */
    public static IkeKePayload createOutboundKePayload(
            @SaProposal.DhGroup int dh, RandomnessFactory randomnessFactory) {
        switch (dh) {
            case SaProposal.DH_GROUP_1024_BIT_MODP: // fall through
            case SaProposal.DH_GROUP_1536_BIT_MODP: // fall through
            case SaProposal.DH_GROUP_2048_BIT_MODP: // fall through
            case SaProposal.DH_GROUP_3072_BIT_MODP: // fall through
            case SaProposal.DH_GROUP_4096_BIT_MODP: // fall through
                return createOutboundModpKePayload(dh, randomnessFactory);
            default:
                throw new IllegalArgumentException("Unsupported DH group: " + dh);
        }
    }

    private static IkeKePayload createOutboundModpKePayload(
            @SaProposal.DhGroup int dh, RandomnessFactory randomnessFactory) {
        BigInteger prime = MODP_PRIME_MAP.get(dh);
        int keySize = PUBLIC_KEY_LEN_MAP.get(dh);
        if (prime == null) {
            throw new IllegalArgumentException("Unsupported MODP DH group: " + dh);
        }

        try {
            BigInteger baseGen = BigInteger.valueOf(IkeDhParams.BASE_GENERATOR_MODP);
            DHParameterSpec dhParams = new DHParameterSpec(prime, baseGen);

            KeyPairGenerator dhKeyPairGen = KeyPairGenerator.getInstance(KEY_EXCHANGE_ALGORITHM);

            SecureRandom random = randomnessFactory.getRandom();
            random = random == null ? new SecureRandom() : random;
            dhKeyPairGen.initialize(dhParams, random);

            KeyPair keyPair = dhKeyPairGen.generateKeyPair();

            PrivateKey localPrivateKey = (DHPrivateKey) keyPair.getPrivate();
            DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

            // Zero-pad the public key without the sign bit
            byte[] keyExchangeData =
                    BigIntegerUtils.bigIntegerToUnsignedByteArray(publicKey.getY(), keySize);

            return new IkeKePayload(dh, keyExchangeData, localPrivateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException("Failed to obtain " + KEY_EXCHANGE_ALGORITHM, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("Failed to initialize key generator", e);
        }
    }

    /**
     * Encode KE payload to ByteBuffer.
     *
     * @param nextPayload type of payload that follows this payload.
     * @param byteBuffer destination ByteBuffer that stores encoded payload.
     */
    @Override
    protected void encodeToByteBuffer(@PayloadType int nextPayload, ByteBuffer byteBuffer) {
        encodePayloadHeaderToByteBuffer(nextPayload, getPayloadLength(), byteBuffer);
        byteBuffer
                .putShort((short) dhGroup)
                .putShort((short) KE_HEADER_RESERVED)
                .put(keyExchangeData);
    }

    /**
     * Get entire payload length.
     *
     * @return entire payload length.
     */
    @Override
    protected int getPayloadLength() {
        return GENERIC_HEADER_LENGTH + KE_HEADER_LEN + keyExchangeData.length;
    }

    /**
     * Calculate the shared secret.
     *
     * @param privateKey the local private key.
     * @param remotePublicKey the public key from remote server.
     * @param dhGroup the DH group.
     * @throws GeneralSecurityException if the remote public key is invalid.
     */
    public static byte[] getSharedKey(PrivateKey privateKey, byte[] remotePublicKey, int dhGroup)
            throws GeneralSecurityException {
        if (!PUBLIC_KEY_LEN_MAP.contains(dhGroup)) {
            throw new IllegalArgumentException("Invalid DH group " + dhGroup);
        }

        KeyAgreement dhKeyAgreement;
        KeyFactory dhKeyFactory;
        try {
            dhKeyAgreement = KeyAgreement.getInstance(KEY_EXCHANGE_ALGORITHM);
            dhKeyFactory = KeyFactory.getInstance(KEY_EXCHANGE_ALGORITHM);

            // Apply local private key.
            dhKeyAgreement.init(privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalArgumentException("Failed to construct or initialize KeyAgreement", e);
        }

        // Build public key.
        BigInteger publicKeyValue = BigIntegerUtils.unsignedByteArrayToBigInteger(remotePublicKey);
        BigInteger primeValue = MODP_PRIME_MAP.get(dhGroup);
        BigInteger baseGenValue = BigInteger.valueOf(IkeDhParams.BASE_GENERATOR_MODP);
        DHPublicKeySpec publicKeySpec =
                new DHPublicKeySpec(publicKeyValue, primeValue, baseGenValue);

        // Validate and apply public key. Validation includes range check as instructed by RFC6989
        // section 2.1
        DHPublicKey publicKey = (DHPublicKey) dhKeyFactory.generatePublic(publicKeySpec);

        dhKeyAgreement.doPhase(publicKey, true /* Last phase */);
        return dhKeyAgreement.generateSecret();
    }

    /**
     * Return the payload type as a String.
     *
     * @return the payload type as a String.
     */
    @Override
    public String getTypeString() {
        return "KE";
    }
}
