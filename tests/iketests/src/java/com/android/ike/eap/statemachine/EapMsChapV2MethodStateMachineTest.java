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

import static com.android.ike.TestUtils.hexStringToByteArray;
import static com.android.ike.eap.message.EapData.EAP_TYPE_MSCHAP_V2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.EapSessionConfig.EapMsChapV2Config;
import com.android.ike.eap.statemachine.EapMsChapV2MethodStateMachine.CreatedState;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class EapMsChapV2MethodStateMachineTest {
    // Test vectors taken from RFC 2759#9.2
    private static final String USERNAME = "User";
    private static final byte[] USERNAME_ASCII_BYTES = hexStringToByteArray("55736572");
    private static final String PASSWORD = "clientPass";
    private static final byte[] PASSWORD_UTF_BYTES =
            hexStringToByteArray("63006C00690065006E0074005000610073007300");
    private static final byte[] AUTHENTICATOR_CHALLENGE =
            hexStringToByteArray("5B5D7C7D7B3F2F3E3C2C602132262628");
    private static final byte[] PEER_CHALLENGE =
            hexStringToByteArray("21402324255E262A28295F2B3A337C7E");
    private static final byte[] CHALLENGE = hexStringToByteArray("D02E4386BCE91226");
    private static final byte[] PASSWORD_HASH =
            hexStringToByteArray("44EBBA8D5312B8D611474411F56989AE");
    private static final byte[] PASSWORD_HASH_HASH =
            hexStringToByteArray("41C00C584BD2D91C4017A2A12FA59F3F");
    private static final byte[] NT_RESPONSE =
            hexStringToByteArray("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
    private static final byte[] AUTHENTICATOR_RESPONSE =
            hexStringToByteArray("407A5589115FD0D6209F510FE9C04566932CDA56");

    private EapMsChapV2Config mEapMsChapV2Config;
    private EapMsChapV2MethodStateMachine mStateMachine;

    @Before
    public void setUp() {
        mEapMsChapV2Config = new EapMsChapV2Config(USERNAME, PASSWORD);
        mStateMachine = new EapMsChapV2MethodStateMachine(mEapMsChapV2Config, new SecureRandom());
    }

    @Test
    public void testGetEapMethod() {
        assertEquals(EAP_TYPE_MSCHAP_V2, mStateMachine.getEapMethod());
    }

    @Test
    public void testStartsOnCreatedState() {
        assertTrue(mStateMachine.getState() instanceof CreatedState);
    }

    // Tests for MS CHAPv2 authentication utils. Test vectors from RFC 2759#9.2.

    @Test
    public void testUsernameToBytes() throws Exception {
        assertArrayEquals(
                USERNAME_ASCII_BYTES, EapMsChapV2MethodStateMachine.usernameToBytes(USERNAME));
    }

    @Test
    public void testPasswordToBytes() throws Exception {
        assertArrayEquals(
                PASSWORD_UTF_BYTES, EapMsChapV2MethodStateMachine.passwordToBytes(PASSWORD));
    }

    @Test
    public void testGenerateNtResponse() throws Exception {
        byte[] ntResponse =
                EapMsChapV2MethodStateMachine.generateNtResponse(
                        AUTHENTICATOR_CHALLENGE, PEER_CHALLENGE, USERNAME, PASSWORD);
        assertArrayEquals(NT_RESPONSE, ntResponse);
    }

    @Test
    public void testChallengeHash() throws Exception {
        byte[] challenge =
                EapMsChapV2MethodStateMachine.challengeHash(
                        PEER_CHALLENGE, AUTHENTICATOR_CHALLENGE, USERNAME);
        assertArrayEquals(CHALLENGE, challenge);
    }

    @Test
    public void testNtPasswordHash() throws Exception {
        byte[] passwordHash = EapMsChapV2MethodStateMachine.ntPasswordHash(PASSWORD);
        assertArrayEquals(PASSWORD_HASH, passwordHash);
    }

    @Test
    public void testHashNtPasswordHash() throws Exception {
        byte[] passwordHashHash = EapMsChapV2MethodStateMachine.hashNtPasswordHash(PASSWORD_HASH);
        assertArrayEquals(PASSWORD_HASH_HASH, passwordHashHash);
    }

    @Test
    public void testChallengeResponse() throws Exception {
        byte[] challengeResponse =
                EapMsChapV2MethodStateMachine.challengeResponse(CHALLENGE, PASSWORD_HASH);
        assertArrayEquals(NT_RESPONSE, challengeResponse);
    }

    @Test
    public void testGenerateAuthenticatorResponse() throws Exception {
        byte[] authenticatorResponse =
                EapMsChapV2MethodStateMachine.generateAuthenticatorResponse(
                        PASSWORD, NT_RESPONSE, PEER_CHALLENGE, AUTHENTICATOR_CHALLENGE, USERNAME);
        assertArrayEquals(AUTHENTICATOR_RESPONSE, authenticatorResponse);
    }

    @Test
    public void testCheckAuthenticatorResponse() throws Exception {
        assertTrue(
                "AuthenticatorResponse didn't match computed response",
                EapMsChapV2MethodStateMachine.checkAuthenticatorResponse(
                        PASSWORD,
                        NT_RESPONSE,
                        PEER_CHALLENGE,
                        AUTHENTICATOR_CHALLENGE,
                        USERNAME,
                        AUTHENTICATOR_RESPONSE));
    }
}
