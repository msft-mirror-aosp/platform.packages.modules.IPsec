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

package com.android.ike.eap.statemachine;

import static com.android.ike.eap.message.EapData.EAP_TYPE_MSCHAP_V2;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapSessionConfig.EapMsChapV2Config;
import com.android.ike.eap.crypto.ParityBitUtil;
import com.android.ike.eap.message.EapData.EapMethod;
import com.android.ike.eap.message.EapMessage;
import com.android.internal.annotations.VisibleForTesting;
import com.android.org.bouncycastle.crypto.digests.MD4Digest;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 * EapMsChapV2MethodStateMachine represents the valid paths possible for the EAP MSCHAPv2 protocol.
 *
 * <p>EAP MSCHAPv2 sessions will always follow the path:
 *
 * <p>CreatedState --> ChallengeState --> PostChallengeState --> FinalState
 *
 * <p>Note: All Failure-Request messages received in the PostChallenge state will be responded to
 * with Failure-Response messages. That is, retryable failures <i>will not</i> be retried.
 *
 * @see <a href="https://tools.ietf.org/html/draft-kamath-pppext-eap-mschapv2-02">Microsoft EAP CHAP
 *     Extensions Draft (EAP MSCHAPv2)</a>
 * @see <a href="https://tools.ietf.org/html/rfc2759">RFC 2759, Microsoft PPP CHAP Extensions,
 *     Version 2 (MSCHAPv2)</a>
 * @see <a href="https://tools.ietf.org/html/rfc3079">RFC 3079, Deriving Keys for use with Microsoft
 *     Point-to-Point Encryption (MPPE)</a>
 */
public class EapMsChapV2MethodStateMachine extends EapMethodStateMachine {
    public static final String SHA_ALG = "SHA-1";
    public static final String DES_ALG = "DES/ECB/NoPadding";
    public static final String DES_KEY_FACTORY = "DES";
    public static final String USERNAME_CHARSET = "US-ASCII";
    public static final String PASSWORD_CHARSET = "UTF-16LE";
    private static final int CHALLENGE_HASH_LEN = 8;
    private static final int PASSWORD_HASH_LEN = 16;
    private static final int PASSWORD_HASH_HASH_LEN = 16;
    private static final int RESPONSE_LEN = 24;
    private static final int Z_PASSWORD_HASH_LEN = 21;
    private static final int Z_PASSWORD_SECTION_LEN = 7;
    private static final int RESPONSE_SECTION_LEN = 8;

    // we all need a little magic in our lives
    // Defined in RFC 2759#8.7. Constants used for response Success response generation.
    private static final byte[] MAGIC_1 = {
        (byte) 0x4D, (byte) 0x61, (byte) 0x67, (byte) 0x69, (byte) 0x63, (byte) 0x20, (byte) 0x73,
        (byte) 0x65, (byte) 0x72, (byte) 0x76, (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x74,
        (byte) 0x6F, (byte) 0x20, (byte) 0x63, (byte) 0x6C, (byte) 0x69, (byte) 0x65, (byte) 0x6E,
        (byte) 0x74, (byte) 0x20, (byte) 0x73, (byte) 0x69, (byte) 0x67, (byte) 0x6E, (byte) 0x69,
        (byte) 0x6E, (byte) 0x67, (byte) 0x20, (byte) 0x63, (byte) 0x6F, (byte) 0x6E, (byte) 0x73,
        (byte) 0x74, (byte) 0x61, (byte) 0x6E, (byte) 0x74
    };
    private static final byte[] MAGIC_2 = {
        (byte) 0x50, (byte) 0x61, (byte) 0x64, (byte) 0x20, (byte) 0x74, (byte) 0x6F, (byte) 0x20,
        (byte) 0x6D, (byte) 0x61, (byte) 0x6B, (byte) 0x65, (byte) 0x20, (byte) 0x69, (byte) 0x74,
        (byte) 0x20, (byte) 0x64, (byte) 0x6F, (byte) 0x20, (byte) 0x6D, (byte) 0x6F, (byte) 0x72,
        (byte) 0x65, (byte) 0x20, (byte) 0x74, (byte) 0x68, (byte) 0x61, (byte) 0x6E, (byte) 0x20,
        (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x20, (byte) 0x69, (byte) 0x74, (byte) 0x65,
        (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6F, (byte) 0x6E
    };

    private final EapMsChapV2Config mEapMsChapV2Config;
    private final SecureRandom mSecureRandom;

    public EapMsChapV2MethodStateMachine(
            EapMsChapV2Config eapMsChapV2Config, SecureRandom secureRandom) {
        this.mEapMsChapV2Config = eapMsChapV2Config;
        this.mSecureRandom = secureRandom;

        transitionTo(new CreatedState());
    }

    @Override
    @EapMethod
    int getEapMethod() {
        return EAP_TYPE_MSCHAP_V2;
    }

    @Override
    EapResult handleEapNotification(String tag, EapMessage message) {
        return EapStateMachine.handleNotification(tag, message);
    }

    protected class CreatedState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/140571186): implement CreatedState
            return null;
        }
    }

    protected class ChallengeState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/140320101): implement ChallengeState
            return null;
        }
    }

    protected class PostChallengeState extends EapMethodState {
        @Override
        public EapResult process(EapMessage message) {
            // TODO(b/140322003): implement PostChallengeState
            return null;
        }
    }

    /** Util for converting String username to "0-to-256 char username", as used in RFC 2759#8. */
    @VisibleForTesting
    static byte[] usernameToBytes(String username) throws UnsupportedEncodingException {
        return username.getBytes(USERNAME_CHARSET);
    }

    /**
     * Util for converting String password to "0-to-256-unicode-char password", as used in
     * RFC 2759#8.
     */
    @VisibleForTesting
    static byte[] passwordToBytes(String password) throws UnsupportedEncodingException {
        return password.getBytes(PASSWORD_CHARSET);
    }

    /* Implementation of RFC 2759#8.1: GenerateNTResponse() */
    @VisibleForTesting
    static byte[] generateNtResponse(
            byte[] authenticatorChallenge, byte[] peerChallenge, String username, String password)
            throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] challenge = challengeHash(peerChallenge, authenticatorChallenge, username);
        byte[] passwordHash = ntPasswordHash(password);
        return challengeResponse(challenge, passwordHash);
    }

    /* Implementation of RFC 2759#8.2: ChallengeHash() */
    @VisibleForTesting
    static byte[] challengeHash(
            byte[] peerChallenge, byte[] authenticatorChallenge, String username)
            throws GeneralSecurityException, UnsupportedEncodingException {
        MessageDigest sha1 = MessageDigest.getInstance(SHA_ALG);
        sha1.update(peerChallenge);
        sha1.update(authenticatorChallenge);
        sha1.update(usernameToBytes(username));
        return Arrays.copyOf(sha1.digest(), CHALLENGE_HASH_LEN);
    }

    /* Implementation of RFC 2759#8.3: NtPasswordHash() */
    @VisibleForTesting
    static byte[] ntPasswordHash(String password) throws UnsupportedEncodingException {
        MD4Digest md4 = new MD4Digest();
        byte[] passwordBytes = passwordToBytes(password);
        md4.update(passwordBytes, 0, passwordBytes.length);

        byte[] passwordHash = new byte[PASSWORD_HASH_LEN];
        md4.doFinal(passwordHash, 0);
        return passwordHash;
    }

    /* Implementation of RFC 2759#8.4: HashNtPasswordHash() */
    @VisibleForTesting
    static byte[] hashNtPasswordHash(byte[] passwordHash) {
        MD4Digest md4 = new MD4Digest();
        md4.update(passwordHash, 0, passwordHash.length);

        byte[] passwordHashHash = new byte[PASSWORD_HASH_HASH_LEN];
        md4.doFinal(passwordHashHash, 0);
        return passwordHashHash;
    }

    /* Implementation of RFC 2759#8.5: ChallengeResponse() */
    @VisibleForTesting
    static byte[] challengeResponse(byte[] challenge, byte[] passwordHash)
            throws GeneralSecurityException {
        byte[] zPasswordHash = Arrays.copyOf(passwordHash, Z_PASSWORD_HASH_LEN);

        ByteBuffer response = ByteBuffer.allocate(RESPONSE_LEN);
        for (int i = 0; i < 3; i++) {
            int from = i * Z_PASSWORD_SECTION_LEN;
            int to = from + Z_PASSWORD_SECTION_LEN;
            byte[] zPasswordSection = Arrays.copyOfRange(zPasswordHash, from, to);
            response.put(desEncrypt(challenge, zPasswordSection));
        }
        return response.array();
    }

    /* Implementation of RFC 2759#8.6: DesEncrypt() */
    @VisibleForTesting
    static byte[] desEncrypt(byte[] clear, byte[] key) throws GeneralSecurityException {
        if (key.length != Z_PASSWORD_SECTION_LEN) {
            throw new IllegalArgumentException("DES Key must be 7B before parity-bits are added");
        }

        key = ParityBitUtil.addParityBits(key);
        SecretKey secretKey =
                SecretKeyFactory.getInstance(DES_KEY_FACTORY).generateSecret(new DESKeySpec(key));

        Cipher des = Cipher.getInstance(DES_ALG);
        des.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] output = des.doFinal(clear);

        // RFC 2759#8.6 specifies 8B outputs for DesEncrypt()
        return Arrays.copyOf(output, RESPONSE_SECTION_LEN);
    }

    /**
     * Implementation of RFC 2759#8.7: GenerateAuthenticatorResponse()
     *
     * <p>Keep response as byte[] so checkAuthenticatorResponse() can easily compare byte[]'s
     */
    @VisibleForTesting
    static byte[] generateAuthenticatorResponse(
            String password,
            byte[] ntResponse,
            byte[] peerChallenge,
            byte[] authenticatorChallenge,
            String username)
            throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] passwordHash = ntPasswordHash(password);
        byte[] passwordHashHash = hashNtPasswordHash(passwordHash);

        MessageDigest sha1 = MessageDigest.getInstance(SHA_ALG);
        sha1.update(passwordHashHash);
        sha1.update(ntResponse);
        sha1.update(MAGIC_1); // add just a dash of magic
        byte[] digest = sha1.digest();

        byte[] challenge = challengeHash(peerChallenge, authenticatorChallenge, username);

        sha1.update(digest);
        sha1.update(challenge);
        sha1.update(MAGIC_2);

        return sha1.digest();
    }

    /* Implementation of RFC 2759#8.8: CheckAuthenticatorResponse() */
    @VisibleForTesting
    static boolean checkAuthenticatorResponse(
            String password,
            byte[] ntResponse,
            byte[] peerChallenge,
            byte[] authenticatorChallenge,
            String userName,
            byte[] receivedResponse)
            throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] myResponse =
                generateAuthenticatorResponse(
                        password, ntResponse, peerChallenge, authenticatorChallenge, userName);
        return Arrays.equals(myResponse, receivedResponse);
    }
}
