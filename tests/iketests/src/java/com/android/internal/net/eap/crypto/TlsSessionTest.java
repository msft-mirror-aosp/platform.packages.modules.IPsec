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

package com.android.internal.net.eap.crypto;

import static com.android.internal.net.TestUtils.hexStringToByteArray;
import static com.android.internal.net.eap.crypto.TlsSession.TLS_STATUS_CLOSED;
import static com.android.internal.net.eap.crypto.TlsSession.TLS_STATUS_FAILURE;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.android.internal.net.eap.crypto.TlsSession.TlsResult;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class TlsSessionTest {

    // Package-private
    SSLEngine mMockSslEngine;
    SSLContext mMockSslContext;
    SSLSession mMockSslSession;
    SecureRandom mMockSecureRandom;
    Runnable mMockRunnable;
    TlsSession mTlsSession;

    static final byte[] SAMPLE_PACKET_TLS_MESSAGE =
            hexStringToByteArray(
                    "16030100a5010000a10303000102030405060708090a0b0c0d0e0f10"
                            + "1112131415161718191a1b1c1d1e1f000020cca8cca9c02fc030c0"
                            + "2bc02cc013c009c014c00a009c009d002f0035c012000a01000058"
                            + "0000001800160000136578616d706c652e75");
    static final byte[] SAMPLE_APPLICATION_TLS_MESSAGE =
            hexStringToByteArray(
                    "16030300310200002d0303707172737475767778797a7b7c7d7e7f808182838485868788"
                            + "898a8b8c8d8e8f00c013000005ff");
    static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    static final int APPLICATION_BUFFER_SIZE_TLS_MESSAGE = 50;
    private static final int PACKET_BUFFER_SIZE_TLS_MESSAGE = 100;

    static final ByteBuffer EMPTY_APPLICATION_BUFFER =
            ByteBuffer.allocate(APPLICATION_BUFFER_SIZE_TLS_MESSAGE);
    static final ByteBuffer EMPTY_PACKET_BUFFER =
            ByteBuffer.allocate(PACKET_BUFFER_SIZE_TLS_MESSAGE);
    static final ByteBuffer APPLICATION_BUFFER_POSITION_RESET =
            (ByteBuffer)
                    ByteBuffer.allocate(APPLICATION_BUFFER_SIZE_TLS_MESSAGE)
                            .put(SAMPLE_APPLICATION_TLS_MESSAGE)
                            .flip();
    static final ByteBuffer PACKET_BUFFER_POSITION_RESET =
            (ByteBuffer)
                    ByteBuffer.allocate(PACKET_BUFFER_SIZE_TLS_MESSAGE)
                            .put(SAMPLE_PACKET_TLS_MESSAGE)
                            .flip();
    static final ByteBuffer PACKET_BUFFER_POSITION_LIMIT =
            ByteBuffer.allocate(PACKET_BUFFER_SIZE_TLS_MESSAGE).put(SAMPLE_PACKET_TLS_MESSAGE);
    static final ByteBuffer APPLICATION_BUFFER_POSITION_LIMIT =
            (ByteBuffer)
                    ByteBuffer.allocate(APPLICATION_BUFFER_SIZE_TLS_MESSAGE)
                            .put(SAMPLE_APPLICATION_TLS_MESSAGE);

    static final SSLEngineResult RESULT_NEED_WRAP_OK =
            new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, 0, 0);
    static final SSLEngineResult RESULT_NEED_WRAP_CLOSED =
            new SSLEngineResult(Status.CLOSED, HandshakeStatus.NEED_WRAP, 0, 0);
    static final SSLEngineResult RESULT_NEED_UNWRAP_OK =
            new SSLEngineResult(Status.OK, HandshakeStatus.NEED_UNWRAP, 0, 0);
    static final SSLEngineResult RESULT_NEED_UNWRAP_OVERFLOW =
            new SSLEngineResult(Status.BUFFER_OVERFLOW, HandshakeStatus.NEED_UNWRAP, 0, 0);
    static final SSLEngineResult RESULT_NEED_UNWRAP_UNDERFLOW =
            new SSLEngineResult(Status.BUFFER_UNDERFLOW, HandshakeStatus.NEED_UNWRAP, 0, 0);
    static final SSLEngineResult RESULT_NEED_UNWRAP_CLOSED =
            new SSLEngineResult(Status.CLOSED, HandshakeStatus.NEED_UNWRAP, 0, 0);
    static final SSLEngineResult RESULT_FINISHED_OK =
            new SSLEngineResult(Status.OK, HandshakeStatus.FINISHED, 0, 0);
    static final SSLEngineResult RESULT_NOT_HANDSHAKING_OK =
            new SSLEngineResult(Status.OK, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    static final SSLEngineResult RESULT_NOT_HANDSHAKING_OVERFLOW =
            new SSLEngineResult(Status.BUFFER_OVERFLOW, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    static final SSLEngineResult RESULT_NOT_HANDSHAKING_UNDERFLOW =
            new SSLEngineResult(Status.BUFFER_UNDERFLOW, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    static final SSLEngineResult RESULT_NOT_HANDSHAKING_CLOSED =
            new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);

    @Before
    public void setUp() {
        mMockSslContext = mock(SSLContext.class);
        mMockSslEngine = mock(SSLEngine.class);
        mMockSslSession = mock(SSLSession.class);
        mMockSecureRandom = mock(SecureRandom.class);
        mMockRunnable = mock(Runnable.class);

        when(mMockSslSession.getApplicationBufferSize())
                .thenReturn(APPLICATION_BUFFER_SIZE_TLS_MESSAGE);
        when(mMockSslSession.getPacketBufferSize()).thenReturn(PACKET_BUFFER_SIZE_TLS_MESSAGE);
        mTlsSession =
                new TlsSession(mMockSslContext, mMockSslEngine, mMockSslSession, mMockSecureRandom);
    }

    @Test
    public void testCloseConnection_success_withData() throws Exception {
        when(mMockSslEngine.getHandshakeStatus()).thenReturn(HandshakeStatus.NEED_WRAP);
        setupWrap(EMPTY_APPLICATION_BUFFER, EMPTY_PACKET_BUFFER, RESULT_NOT_HANDSHAKING_CLOSED);

        TlsResult result = mTlsSession.closeConnection();

        assertEquals(TLS_STATUS_CLOSED, result.status);
        assertArrayEquals(SAMPLE_PACKET_TLS_MESSAGE, result.data);
        verify(mMockSslEngine).wrap(eq(EMPTY_APPLICATION_BUFFER), eq(PACKET_BUFFER_POSITION_LIMIT));
    }

    @Test
    public void testCloseConnection_success_withoutData() throws Exception {
        when(mMockSslEngine.getHandshakeStatus()).thenReturn(HandshakeStatus.NOT_HANDSHAKING);

        TlsResult result = mTlsSession.closeConnection();

        assertEquals(TLS_STATUS_CLOSED, result.status);
        assertArrayEquals(EMPTY_BYTE_ARRAY, result.data);
    }

    @Test
    public void testCloseConnection_failure_sslException() throws Exception {
        when(mMockSslEngine.getHandshakeStatus()).thenReturn(HandshakeStatus.NEED_WRAP);
        when(mMockSslEngine.wrap(eq(EMPTY_APPLICATION_BUFFER), eq(EMPTY_PACKET_BUFFER)))
                .thenThrow(SSLException.class);

        TlsResult result = mTlsSession.closeConnection();

        assertEquals(TLS_STATUS_FAILURE, result.status);
        assertArrayEquals(EMPTY_BYTE_ARRAY, result.data);
        verify(mMockSslEngine).wrap(eq(EMPTY_APPLICATION_BUFFER), eq(EMPTY_PACKET_BUFFER));
    }

    @Test
    public void testCloseConnection_failure_bufferOverflow() throws Exception {
        when(mMockSslEngine.getHandshakeStatus()).thenReturn(HandshakeStatus.NEED_WRAP);
        when(mMockSslEngine.wrap(eq(EMPTY_APPLICATION_BUFFER), eq(EMPTY_PACKET_BUFFER)))
                .thenReturn(RESULT_NEED_UNWRAP_OVERFLOW);

        TlsResult result = mTlsSession.closeConnection();

        assertEquals(TLS_STATUS_FAILURE, result.status);
        assertArrayEquals(EMPTY_BYTE_ARRAY, result.data);
        verify(mMockSslEngine).wrap(eq(EMPTY_APPLICATION_BUFFER), eq(EMPTY_PACKET_BUFFER));
    }

    /**
     * Mocks a wrap operation and inserts data into the packet buffer
     *
     * @param applicationBuffer the application (source) buffer
     * @param packetBuffer the packet (destination) buffer
     * @param result the SSLEngineResult to return
     */
    void setupWrap(ByteBuffer applicationBuffer, ByteBuffer packetBuffer, SSLEngineResult result)
            throws Exception {
        when(mMockSslEngine.wrap(eq(applicationBuffer), eq(packetBuffer)))
                .thenAnswer(
                        invocation -> {
                            ByteBuffer buffer = invocation.getArgument(1);
                            buffer.put(SAMPLE_PACKET_TLS_MESSAGE);
                            return result;
                        });
    }

    /**
     * Mocks a chained wrap operation and inserts data into the packet buffer
     *
     * @param applicationBuffer the application (source) buffer
     * @param packetBuffer the packet (destination) buffer
     * @param firstResult the first SSLEngineResult to return
     * @param secondResult the second SSLEngineResult to return
     */
    void setupChainedWrap(
            ByteBuffer applicationBuffer,
            ByteBuffer packetBuffer,
            SSLEngineResult firstResult,
            SSLEngineResult secondResult)
            throws Exception {
        when(mMockSslEngine.wrap(eq(applicationBuffer), eq(packetBuffer)))
                .thenReturn(firstResult)
                .thenAnswer(
                        invocation -> {
                            ByteBuffer buffer = invocation.getArgument(1);
                            buffer.put(SAMPLE_PACKET_TLS_MESSAGE);
                            return secondResult;
                        });
    }

    /**
     * Mocks an unwrap operation and inserts data into the application buffer
     *
     * @param applicationBuffer the application (destination) buffer
     * @param packetBuffer the packet (source) buffer
     * @param result the SSLEngineResult to return
     */
    void setupUnwrap(ByteBuffer applicationBuffer, ByteBuffer packetBuffer, SSLEngineResult result)
            throws Exception {
        when(mMockSslEngine.unwrap(eq(packetBuffer), eq(applicationBuffer)))
                .thenAnswer(
                        invocation -> {
                            ByteBuffer buffer = invocation.getArgument(1);
                            buffer.put(SAMPLE_APPLICATION_TLS_MESSAGE);
                            return result;
                        });
    }

    /**
     * Mocks a chained wrap operation and inserts data into the packet buffer
     *
     * <p>The first result during a wrap will be an exception in this case
     *
     * @param applicationBuffer the application (source) buffer
     * @param packetBuffer the packet (destination) buffer
     * @param result the SSLEngineResult to return
     */
    void setupChainedWrap_exception(
            ByteBuffer applicationBuffer, ByteBuffer packetBuffer, SSLEngineResult result)
            throws Exception {
        when(mMockSslEngine.wrap(eq(applicationBuffer), eq(packetBuffer)))
                .thenThrow(SSLException.class)
                .thenAnswer(
                        invocation -> {
                            ByteBuffer buffer = invocation.getArgument(1);
                            buffer.put(SAMPLE_PACKET_TLS_MESSAGE);
                            return result;
                        });
    }
}
