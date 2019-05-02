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
package com.android.ike.ikev2;

import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.ike.ikev2.message.IkeKePayload;
import com.android.ike.ikev2.message.IkeMessage;
import com.android.ike.ikev2.message.IkeNoncePayload;
import com.android.ike.ikev2.message.IkePayload;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * SaRecord represents common information of an IKE SA and a Child SA.
 *
 * <p>When doing rekey, there can be multiple SAs in the same IkeSessionStateMachine or
 * ChildSessionStateMachine, where they use same cryptographic algorithms but with different keys.
 * We store cryptographic algorithms and unchanged SA configurations in IkeSessionOptions or
 * ChildSessionOptions and store changed information including keys, SPIs, and nonces in SaRecord.
 */
public abstract class SaRecord {

    private static ISaRecordHelper sSaRecordHelper = new SaRecordHelper();

    /** Flag indicates if this SA is locally initiated */
    public final boolean isLocalInit;

    public final byte[] nonceInitiator;
    public final byte[] nonceResponder;

    private final byte[] mSkAi;
    private final byte[] mSkAr;
    private final byte[] mSkEi;
    private final byte[] mSkEr;

    /** Package private */
    SaRecord(
            boolean localInit,
            byte[] nonceInit,
            byte[] nonceResp,
            byte[] skAi,
            byte[] skAr,
            byte[] skEi,
            byte[] skEr) {
        isLocalInit = localInit;
        nonceInitiator = nonceInit;
        nonceResponder = nonceResp;

        mSkAi = skAi;
        mSkAr = skAr;
        mSkEi = skEi;
        mSkEr = skEr;
    }

    /**
     * Get the integrity key for calculate integrity checksum for an outbound packet.
     *
     * @return the integrity key in a byte array, which will be empty if integrity algorithm is not
     *     used in this SA.
     */
    public byte[] getOutboundIntegrityKey() {
        return isLocalInit ? mSkAi : mSkAr;
    }

    /**
     * Get the integrity key to authenticate an inbound packet.
     *
     * @return the integrity key in a byte array, which will be empty if integrity algorithm is not
     *     used in this SA.
     */
    public byte[] getInboundIntegrityKey() {
        return isLocalInit ? mSkAr : mSkAi;
    }

    /**
     * Get the encryption key for protecting an outbound packet.
     *
     * @return the encryption key in a byte array.
     */
    public byte[] getOutboundEncryptionKey() {
        return isLocalInit ? mSkEi : mSkEr;
    }

    /**
     * Get the decryption key for an inbound packet.
     *
     * @return the decryption key in a byte array.
     */
    public byte[] getInboundDecryptionKey() {
        return isLocalInit ? mSkEr : mSkEi;
    }

    /**
     * SaRecordHelper implements methods for constructing SaRecord.
     *
     * <p>Package private
     */
    static class SaRecordHelper implements ISaRecordHelper {
        @Override
        public IkeSaRecord makeFirstIkeSaRecord(
                IkeMessage initRequest,
                IkeMessage initResponse,
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength)
                throws GeneralSecurityException {
            // Extract nonces
            byte[] nonceInit =
                    initRequest.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class)
                            .nonceData;
            byte[] nonceResp =
                    initResponse.getPayloadForType(
                                    IkePayload.PAYLOAD_TYPE_NONCE, IkeNoncePayload.class)
                            .nonceData;

            // Get SKEYSEED
            byte[] sharedDhKey = getSharedKey(initRequest, initResponse);
            byte[] sKeySeed = prf.generateSKeySeed(nonceInit, nonceResp, sharedDhKey);

            return makeIkeSaRecord(
                    prf,
                    integrityKeyLength,
                    encryptionKeyLength,
                    sKeySeed,
                    nonceInit,
                    nonceResp,
                    initResponse.ikeHeader.ikeInitiatorSpi,
                    initResponse.ikeHeader.ikeResponderSpi,
                    true /*isLocalInit*/);
        }

        @Override
        public IkeSaRecord makeNewIkeSaRecord(
                IkeSaRecord oldSaRecord, IkeMessage rekeyRequest, IkeMessage rekeyResponse) {
            // TODO: Generate keying materials based on old SK_d
            return null;
        }

        private byte[] getSharedKey(IkeMessage initRequest, IkeMessage initResponse)
                throws GeneralSecurityException {
            IkeKePayload keInitPayload =
                    initRequest.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);
            IkeKePayload keRespPayload =
                    initResponse.getPayloadForType(IkePayload.PAYLOAD_TYPE_KE, IkeKePayload.class);

            return IkeKePayload.getSharedKey(
                    keInitPayload.localPrivateKey, keRespPayload.keyExchangeData);
        }

        /**
         * Package private method for calculating keys and construct IkeSaRecord.
         *
         * @see <a href="https://tools.ietf.org/html/rfc7296#section-2.13">RFC 7296, Internet Key
         *     Exchange Protocol Version 2 (IKEv2), Generating Keying Material</a>
         */
        @VisibleForTesting
        IkeSaRecord makeIkeSaRecord(
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength,
                byte[] sKeySeed,
                byte[] nonceInit,
                byte[] nonceResp,
                long initSpi,
                long respSpi,
                boolean isLocalInit) {
            // Build data to sign for generating the keying material.
            ByteBuffer bufferToSign =
                    ByteBuffer.allocate(
                            nonceInit.length + nonceResp.length + 2 * IkePayload.SPI_LEN_IKE);
            bufferToSign.put(nonceInit).put(nonceResp).putLong(initSpi).putLong(respSpi);

            // Get length of the keying material according to RFC 7296, 2.13 and 2.14. The length of
            // SK_D is always equal to the length of PRF key.
            int skDLength = prf.getKeyLength();
            int keyMaterialLen =
                    skDLength
                            + 2 * integrityKeyLength
                            + 2 * encryptionKeyLength
                            + 2 * prf.getKeyLength();
            byte[] keyMat = prf.generateKeyMat(sKeySeed, bufferToSign.array(), keyMaterialLen);

            // Extract keys.
            byte[] skD = new byte[skDLength];
            byte[] skAi = new byte[integrityKeyLength];
            byte[] skAr = new byte[integrityKeyLength];
            byte[] skEi = new byte[encryptionKeyLength];
            byte[] skEr = new byte[encryptionKeyLength];
            byte[] skPi = new byte[prf.getKeyLength()];
            byte[] skPr = new byte[prf.getKeyLength()];

            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMat);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            return new IkeSaRecord(
                    initSpi,
                    respSpi,
                    true /*localInit*/,
                    nonceInit,
                    nonceResp,
                    skD,
                    skAi,
                    skAr,
                    skEi,
                    skEr,
                    skPi,
                    skPr);
        }

        @Override
        public ChildSaRecord makeChildSaRecord(
                List<IkePayload> reqPayloads, List<IkePayload> respPayloads) {
            // TODO: Calculate keys and build IpSecTransform.
            return null;
        }
    }

    /** Package private */
    static void setSaRecordHelper(ISaRecordHelper helper) {
        sSaRecordHelper = helper;
    }

    /** IkeSaRecord represents an IKE SA. */
    public static class IkeSaRecord extends SaRecord implements Comparable<IkeSaRecord> {

        /** SPI of IKE SA initiator */
        public final long initiatorSpi;
        /** SPI of IKE SA responder */
        public final long responderSpi;

        private final byte[] mSkD;
        private final byte[] mSkPi;
        private final byte[] mSkPr;

        private int mLocalRequestMessageId;
        private int mRemoteRequestMessageId;

        /** Package private */
        IkeSaRecord(
                long initSpi,
                long respSpi,
                boolean localInit,
                byte[] nonceInit,
                byte[] nonceResp,
                byte[] skD,
                byte[] skAi,
                byte[] skAr,
                byte[] skEi,
                byte[] skEr,
                byte[] skPi,
                byte[] skPr) {
            super(localInit, nonceInit, nonceResp, skAi, skAr, skEi, skEr);

            initiatorSpi = initSpi;
            responderSpi = respSpi;

            mSkD = skD;
            mSkPi = skPi;
            mSkPr = skPr;

            mLocalRequestMessageId = 0;
            mRemoteRequestMessageId = 0;
        }

        /** Package private */
        static IkeSaRecord makeFirstIkeSaRecord(
                IkeMessage initRequest,
                IkeMessage initResponse,
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength)
                throws GeneralSecurityException {
            return sSaRecordHelper.makeFirstIkeSaRecord(
                    initRequest, initResponse, prf, integrityKeyLength, encryptionKeyLength);
        }

        /** Package private */
        static IkeSaRecord makeNewIkeSaRecord(
                IkeSaRecord oldSaRecord, IkeMessage rekeyRequest, IkeMessage rekeyResponse) {
            return sSaRecordHelper.makeNewIkeSaRecord(oldSaRecord, rekeyRequest, rekeyResponse);
        }

        /** Package private */
        long getRemoteSpi() {
            return isLocalInit ? responderSpi : initiatorSpi;
        }
        /** Package private */
        byte[] getSkD() {
            return mSkD;
        }

        /**
         * Get the PRF key of IKE initiator for building an outbound Auth Payload.
         *
         * @return the PRF key in a byte array.
         */
        public byte[] getSkPi() {
            return mSkPi;
        }

        /**
         * Get the PRF key of IKE responder for validating an inbound Auth Payload.
         *
         * @return the PRF key in a byte array.
         */
        public byte[] getSkPr() {
            return mSkPr;
        }

        /**
         * Compare with a specific IkeSaRecord
         *
         * @param record IkeSaRecord to be compared.
         * @return a negative integer if input IkeSaRecord contains lowest nonce; a positive integer
         *     if this IkeSaRecord has lowest nonce; return zero if lowest nonces of two
         *     IkeSaRecords match.
         */
        public int compareTo(IkeSaRecord record) {
            // TODO: Implement it b/122924815.
            return 1;
        }

        /**
         * Get current message ID for the local requesting window.
         *
         * <p>Called for building an outbound request or for validating the message ID of an inbound
         * response.
         *
         * @return the local request message ID.
         */
        public int getLocalRequestMessageId() {
            return mLocalRequestMessageId;
        }

        /**
         * Get current message ID for the remote requesting window.
         *
         * <p>Called for validating the message ID of an inbound request. If the message ID of the
         * inbound request is smaller than the current remote message ID by one, it means the
         * message is a retransmitted request.
         *
         * @return the remote request message ID
         */
        public int getRemoteRequestMessageId() {
            return mRemoteRequestMessageId;
        }

        /**
         * Increment the local request message ID by one.
         *
         * <p>It should be called when IKE library has received an authenticated and protected
         * response with the correct local request message ID.
         */
        public void incrementLocalRequestMessageId() {
            mLocalRequestMessageId++;
        }

        /**
         * Increment the remote request message ID by one.
         *
         * <p>It should be called when IKE library has received an authenticated and protected
         * request with the correct remote request message ID.
         */
        public void incrementRemoteRequestMessageId() {
            mRemoteRequestMessageId++;
        }
    }

    /** ChildSaRecord represents an Child SA. */
    public static class ChildSaRecord extends SaRecord implements Comparable<ChildSaRecord> {

        /** Locally generated SPI for receiving IPsec Packet. */
        public final int inboundSpi;
        /** Remotely generated SPI for sending IPsec Packet. */
        public final int outboundSpi;

        /** Package private */
        ChildSaRecord(
                int inSpi,
                int outSpi,
                boolean localInit,
                byte[] nonceInit,
                byte[] nonceResp,
                byte[] skAi,
                byte[] skAr,
                byte[] skEi,
                byte[] skEr) {
            super(localInit, nonceInit, nonceResp, skAi, skAr, skEi, skEr);

            inboundSpi = inSpi;
            outboundSpi = outSpi;
            // TODO: Impement constructor. Will be more input parameters.
        }

        /** Package private */
        static ChildSaRecord makeChildSaRecord(
                List<IkePayload> reqPayloads, List<IkePayload> respPayloads) {
            return sSaRecordHelper.makeChildSaRecord(reqPayloads, respPayloads);
        }

        /**
         * Compare with a specific ChildSaRecord
         *
         * @param record ChildSaRecord to be compared.
         * @return a negative integer if input ChildSaRecord contains lowest nonce; a positive
         *     integer if this ChildSaRecord has lowest nonce; return zero if lowest nonces of two
         *     ChildSaRecord match.
         */
        public int compareTo(ChildSaRecord record) {
            // TODO: Implement it b/122924815
            return 1;
        }
    }

    /**
     * ISaRecordHelper provides a package private interface for constructing SaRecord.
     *
     * <p>ISaRecordHelper exists so that the interface is injectable for testing.
     */
    interface ISaRecordHelper {
        /**
         * Construct IkeSaRecord as results of IKE initial exchange.
         *
         * @param initRequest IKE_INIT request.
         * @param initResponse IKE_INIT request.
         * @param prf the negotiated PRF.
         * @param integrityKeyLength the key length of the negotiated integrity algorithm.
         * @param encryptionKeyLength the key length of the negotiated encryption algorithm.
         * @return ikeSaRecord for initial IKE SA.
         * @throws GeneralSecurityException if the DH public key in the response is invalid.
         */
        IkeSaRecord makeFirstIkeSaRecord(
                IkeMessage initRequest,
                IkeMessage initResponse,
                IkeMacPrf prf,
                int integrityKeyLength,
                int encryptionKeyLength)
                throws GeneralSecurityException;

        /**
         * Construct new IkeSaRecord when doing rekey.
         *
         * @param oldSaRecord old IKE SA
         * @param rekeyRequest Rekey IKE request.
         * @param rekeyResponse Rekey IKE response.
         * @return ikeSaRecord for new IKE SA.
         */
        IkeSaRecord makeNewIkeSaRecord(
                IkeSaRecord oldSaRecord, IkeMessage rekeyRequest, IkeMessage rekeyResponse);

        /**
         * Construct ChildSaRecord and generate IpSecTransform pairs.
         *
         * @param reqPayloads payload list in request.
         * @param respPayloads payload list in response.
         * @return new Child SA.
         */
        ChildSaRecord makeChildSaRecord(
                List<IkePayload> reqPayloads, List<IkePayload> respPayloads);
    }
}
