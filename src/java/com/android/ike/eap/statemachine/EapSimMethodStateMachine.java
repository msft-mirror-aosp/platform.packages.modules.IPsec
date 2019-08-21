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

import static com.android.ike.eap.EapAuthenticator.LOG;
import static com.android.ike.eap.message.EapData.EAP_NOTIFICATION;
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_FAILURE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_REQUEST;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_RESPONSE;
import static com.android.ike.eap.message.EapMessage.EAP_CODE_SUCCESS;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_ANY_ID_REQ;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_ENCR_DATA;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_FULLAUTH_ID_REQ;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_IV;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_MAC;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_NOTIFICATION;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_PERMANENT_ID_REQ;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_RAND;
import static com.android.ike.eap.message.simaka.EapSimAkaAttribute.EAP_AT_VERSION_LIST;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_CHALLENGE;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_CLIENT_ERROR;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_NOTIFICATION;
import static com.android.ike.eap.message.simaka.EapSimTypeData.EAP_SIM_START;

import android.annotation.Nullable;
import android.content.Context;
import android.telephony.TelephonyManager;
import android.util.Base64;

import com.android.ike.eap.EapResult;
import com.android.ike.eap.EapResult.EapError;
import com.android.ike.eap.EapResult.EapFailure;
import com.android.ike.eap.EapResult.EapResponse;
import com.android.ike.eap.EapResult.EapSuccess;
import com.android.ike.eap.EapSessionConfig.EapSimConfig;
import com.android.ike.eap.crypto.Fips186_2Prf;
import com.android.ike.eap.exceptions.EapInvalidRequestException;
import com.android.ike.eap.exceptions.EapSilentException;
import com.android.ike.eap.exceptions.simaka.EapSimAkaInvalidAttributeException;
import com.android.ike.eap.exceptions.simaka.EapSimIdentityUnavailableException;
import com.android.ike.eap.exceptions.simaka.EapSimInvalidLengthException;
import com.android.ike.eap.message.EapData;
import com.android.ike.eap.message.EapData.EapMethod;
import com.android.ike.eap.message.EapMessage;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtClientErrorCode;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtIdentity;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtMac;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtNonceMt;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtNotification;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtRandSim;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtSelectedVersion;
import com.android.ike.eap.message.simaka.EapSimAkaAttribute.AtVersionList;
import com.android.ike.eap.message.simaka.EapSimTypeData;
import com.android.ike.eap.message.simaka.EapSimTypeData.EapSimTypeDataDecoder;
import com.android.ike.eap.message.simaka.EapSimTypeData.EapSimTypeDataDecoder.DecodeResult;
import com.android.internal.annotations.VisibleForTesting;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * EapSimMethodStateMachine represents the valid paths possible for the EAP-SIM protocol.
 *
 * <p>EAP-SIM procedures will always follow the path:
 *
 * Created ---> Start --+--> Challenge --+--> null
 *                      |                |
 *                      +-->  failed  >--+
 *
 * Note that EAP-SIM/Notification messages can be received at any point in the above state machine.
 * At most one EAP-SIM/Notification message is allowed per EAP-SIM session.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4186">RFC 4186, Extensible Authentication Protocol
 * Method for Subscriber Identity Modules (EAP-SIM)</a>
 */
class EapSimMethodStateMachine extends EapMethodStateMachine {
    private static final String TAG = EapSimMethodStateMachine.class.getSimpleName();

    private final TelephonyManager mTelephonyManager;
    private final EapSimConfig mEapSimConfig;
    private final SecureRandom mSecureRandom;
    private final EapSimTypeDataDecoder mEapSimTypeDataDecoder;

    @VisibleForTesting Mac mMacAlgorithm;
    @VisibleForTesting boolean mHasReceivedSimNotification = false;

    EapSimMethodStateMachine(
            Context context, EapSimConfig eapSimConfig, SecureRandom secureRandom) {
        this(
                (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE),
                eapSimConfig,
                secureRandom,
                new EapSimTypeDataDecoder());
    }

    @VisibleForTesting
    EapSimMethodStateMachine(
            TelephonyManager telephonyManager,
            EapSimConfig eapSimConfig,
            SecureRandom secureRandom,
            EapSimTypeDataDecoder eapSimTypeDataDecoder) {
        if (telephonyManager == null) {
            throw new IllegalArgumentException("TelephonyManager must be non-null");
        } else if (eapSimTypeDataDecoder == null) {
            throw new IllegalArgumentException("EapSimTypeDataDecoder must be non-null");
        }

        this.mTelephonyManager = telephonyManager.createForSubscriptionId(eapSimConfig.subId);
        this.mEapSimConfig = eapSimConfig;
        this.mSecureRandom = secureRandom;
        this.mEapSimTypeDataDecoder = eapSimTypeDataDecoder;
        transitionTo(new CreatedState());
    }

    @Override
    @EapMethod
    int getEapMethod() {
        return EAP_TYPE_SIM;
    }

    @VisibleForTesting
    protected SimpleState getState() {
        return mState;
    }

    @VisibleForTesting
    protected void transitionTo(EapSimState newState) {
        super.transitionTo(newState);
    }

    protected abstract class EapSimState extends SimpleState {
    }

    protected class CreatedState extends EapSimState {
        private final String mTAG = CreatedState.class.getSimpleName();

        public EapResult process(EapMessage message) {
            if (message.eapCode == EAP_CODE_SUCCESS) {
                // EAP-SUCCESS is required to be the last EAP message sent during the EAP protocol,
                // so receiving a premature SUCCESS message is an unrecoverable error.
                return new EapError(
                        new EapInvalidRequestException(
                                "Received an EAP-Success in the CreatedState"));
            } else if (message.eapCode == EAP_CODE_FAILURE) {
                transitionTo(new FinalState());
                return new EapFailure();
            } else if (message.eapData.eapType == EAP_NOTIFICATION) {
                return handleEapNotification(mTAG, message);
            }

            if (message.eapData.eapType != getEapMethod()) {
                return new EapError(new EapInvalidRequestException(
                        "Expected EAP Type " + getEapMethod()
                                + ", received " + message.eapData.eapType));
            }

            DecodeResult decodeResult = mEapSimTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(message.eapIdentifier,
                        decodeResult.atClientErrorCode);
            }

            EapSimTypeData eapSimTypeData = decodeResult.eapSimTypeData;
            switch (eapSimTypeData.eapSubtype) {
                case EAP_SIM_START:
                    break;
                case EAP_SIM_NOTIFICATION:
                    return handleEapSimNotification(
                            true, // isPreChallengeState
                            message.eapIdentifier,
                            eapSimTypeData);
                default:
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            byte[] nonce = new byte[AtNonceMt.NONCE_MT_LENGTH];
            mSecureRandom.nextBytes(nonce);
            AtNonceMt atNonceMt;
            try {
                atNonceMt = new AtNonceMt(nonce);
            } catch (EapSimAkaInvalidAttributeException ex) {
                LOG.wtf(mTAG, "Exception thrown while creating AtNonceMt", ex);
                return new EapError(ex);
            }
            return transitionAndProcess(new StartState(atNonceMt), message);
        }
    }

    protected class StartState extends EapSimState {
        private final String mTAG = StartState.class.getSimpleName();
        private final AtNonceMt mAtNonceMt;

        private List<Integer> mVersions;
        @VisibleForTesting byte[] mIdentity;

        protected StartState(AtNonceMt atNonceMt) {
            this.mAtNonceMt = atNonceMt;
        }

        public EapResult process(EapMessage message) {
            if (message.eapCode == EAP_CODE_SUCCESS) {
                // EAP-SUCCESS is required to be the last EAP message sent during the EAP protocol,
                // so receiving a premature SUCCESS message is an unrecoverable error.
                return new EapError(
                        new EapInvalidRequestException(
                                "Received an EAP-Success in the StartState"));
            } else if (message.eapCode == EAP_CODE_FAILURE) {
                transitionTo(new FinalState());
                return new EapFailure();
            } else if (message.eapData.eapType == EAP_NOTIFICATION) {
                return handleEapNotification(mTAG, message);
            }

            if (message.eapData.eapType != getEapMethod()) {
                return new EapError(new EapInvalidRequestException(
                        "Expected EAP Type " + getEapMethod()
                                + ", received " + message.eapData.eapType));
            }

            DecodeResult decodeResult = mEapSimTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(message.eapIdentifier,
                        decodeResult.atClientErrorCode);
            }

            EapSimTypeData eapSimTypeData = decodeResult.eapSimTypeData;
            switch (eapSimTypeData.eapSubtype) {
                case EAP_SIM_START:
                    break;
                case EAP_SIM_NOTIFICATION:
                    return handleEapSimNotification(
                            true, // isPreChallengeState
                            message.eapIdentifier,
                            eapSimTypeData);
                case EAP_SIM_CHALLENGE:
                    // By virtue of being in the StartState, we have received (and processed) the
                    // EAP-SIM/Start request. Receipt of an EAP-SIM/Challenge request indicates that
                    // the server has accepted our EAP-SIM/Start response, including our identity
                    // (if any).
                    return transitionAndProcess(
                            new ChallengeState(mVersions, mAtNonceMt, mIdentity), message);
                default:
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            if (!isValidStartAttributes(eapSimTypeData)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            List<EapSimAkaAttribute> responseAttributes = new ArrayList<>();
            responseAttributes.add(mAtNonceMt);

            // choose EAP-SIM version
            AtVersionList atVersionList = (AtVersionList)
                    eapSimTypeData.attributeMap.get(EAP_AT_VERSION_LIST);
            mVersions = atVersionList.versions;
            if (!mVersions.contains(AtSelectedVersion.SUPPORTED_VERSION)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNSUPPORTED_VERSION);
            }
            responseAttributes.add(AtSelectedVersion.getSelectedVersion());

            try {
                AtIdentity atIdentity = getIdentityResponse(eapSimTypeData);
                if (atIdentity != null) {
                    responseAttributes.add(atIdentity);
                }
            } catch (EapSimAkaInvalidAttributeException ex) {
                LOG.wtf(mTAG, "Exception thrown while making AtIdentity attribute", ex);
                return new EapError(ex);
            } catch (EapSimIdentityUnavailableException ex) {
                LOG.e(mTAG, "Unable to get IMSI for subId=" + mEapSimConfig.subId);
                return new EapError(ex);
            }

            return buildResponseMessage(EAP_SIM_START, message.eapIdentifier, responseAttributes);
        }

        /**
         * Returns true iff the given EapSimTypeData meets the following conditions:
         *  - contains an AT_VERSION_LIST attribute
         *  - contains at most one of AT_PERMANENT_ID_REQ, AT_ANY_ID_REQ, or AT_FULLAUTH_D_REQ
         *      attributes
         *  - does not contain AT_MAC, AT_IV, or AT_ENCR_DATA attributes
         */
        @VisibleForTesting
        boolean isValidStartAttributes(EapSimTypeData eapSimTypeData) {
            // must contain: version list
            Set<Integer> attrs = eapSimTypeData.attributeMap.keySet();
            if (!attrs.contains(EAP_AT_VERSION_LIST)) {
                return false;
            }

            // may contain: ID request (but only 1)
            int idRequests = 0;
            if (attrs.contains(EAP_AT_PERMANENT_ID_REQ)) {
                idRequests++;
            }
            if (attrs.contains(EAP_AT_ANY_ID_REQ)) {
                idRequests++;
            }
            if (attrs.contains(EAP_AT_FULLAUTH_ID_REQ)) {
                idRequests++;
            }
            if (idRequests > 1) {
                return false;
            }

            // can't contain mac, iv, encr data
            if (attrs.contains(EAP_AT_MAC)
                    || attrs.contains(EAP_AT_IV)
                    || attrs.contains(EAP_AT_ENCR_DATA)) {
                return false;
            }
            return true;
        }

        @VisibleForTesting
        @Nullable
        AtIdentity getIdentityResponse(EapSimTypeData eapSimTypeData)
                throws EapSimAkaInvalidAttributeException, EapSimIdentityUnavailableException {
            Set<Integer> attributes = eapSimTypeData.attributeMap.keySet();

            // TODO(b/136180022): process separate ID requests differently (pseudonym vs permanent)
            if (attributes.contains(EAP_AT_PERMANENT_ID_REQ)
                    || attributes.contains(EAP_AT_FULLAUTH_ID_REQ)
                    || attributes.contains(EAP_AT_ANY_ID_REQ)) {
                String imsi = mTelephonyManager.getSubscriberId();
                if (imsi == null) {
                    throw new EapSimIdentityUnavailableException(
                            "IMSI for subId (" + mEapSimConfig.subId + ") not available");
                }

                // Permanent Identity is "1" + IMSI (RFC 4186 Section 4.1.2.6)
                String identity = "1" + imsi;
                mIdentity = identity.getBytes();

                // Log requested EAP-SIM/Identity as PII
                LOG.d(mTAG, "requested EAP-SIM/Identity=" + LOG.pii(mIdentity));

                return AtIdentity.getAtIdentity(mIdentity);
            }

            return null;
        }
    }

    protected class ChallengeState extends EapSimState {
        private final String mTAG = ChallengeState.class.getSimpleName();
        private final int mBytesPerShort = 2;
        private final int mVersionLenBytes = 2;

        // K_encr and K_aut lengths are 16 bytes (RFC 4186 Section 7)
        private final int mKeyLen = 16;

        // Session Key lengths are 64 bytes (RFC 4186 Section 7)
        private final int mSessionKeyLength = 64;

        // Lengths defined by TS 31.102 Section 7.1.2.1 (case 3)
        // SRES stands for "SIM response"
        // Kc stands for "cipher key"
        private final int mSresLenBytes = 4;
        private final int mKcLenBytes = 8;

        @VisibleForTesting final String mMasterKeyGenerationAlg = "SHA-1";
        @VisibleForTesting final String mMacAlgorithmString = "HmacSHA1";

        private final List<Integer> mVersions;
        private final byte[] mNonce;
        private final byte[] mIdentity;

        @VisibleForTesting final byte[] mKEncr = new byte[mKeyLen];
        @VisibleForTesting final byte[] mKAut = new byte[mKeyLen];
        @VisibleForTesting final byte[] mMsk = new byte[mSessionKeyLength];
        @VisibleForTesting final byte[] mEmsk = new byte[mSessionKeyLength];

        protected ChallengeState(List<Integer> versions, AtNonceMt atNonceMt, byte[] identity) {
            mVersions = versions;
            mNonce = atNonceMt.nonceMt;
            mIdentity = identity;
        }

        public EapResult process(EapMessage message) {
            if (message.eapCode == EAP_CODE_SUCCESS) {
                transitionTo(new FinalState());
                return new EapSuccess(mMsk, mEmsk);
            } else if (message.eapCode == EAP_CODE_FAILURE) {
                transitionTo(new FinalState());
                return new EapFailure();
            } else if (message.eapData.eapType == EAP_NOTIFICATION) {
                return handleEapNotification(mTAG, message);
            }

            if (message.eapData.eapType != getEapMethod()) {
                return new EapError(new EapInvalidRequestException(
                        "Expected EAP Type " + getEapMethod()
                                + ", received " + message.eapData.eapType));
            }

            DecodeResult decodeResult = mEapSimTypeDataDecoder.decode(message.eapData.eapTypeData);
            if (!decodeResult.isSuccessfulDecode()) {
                return buildClientErrorResponse(message.eapIdentifier,
                        decodeResult.atClientErrorCode);
            }

            EapSimTypeData eapSimTypeData = decodeResult.eapSimTypeData;
            switch (eapSimTypeData.eapSubtype) {
                case EAP_SIM_NOTIFICATION:
                    return handleEapSimNotification(
                            false, // isPreChallengeState
                            message.eapIdentifier,
                            eapSimTypeData);
                case EAP_SIM_CHALLENGE:
                    break;
                default:
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            if (!isValidChallengeAttributes(eapSimTypeData)) {
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            List<RandChallengeResult> randChallengeResults;
            try {
                randChallengeResults = getRandChallengeResults(eapSimTypeData);
            } catch (EapSimInvalidLengthException | BufferUnderflowException ex) {
                LOG.e(mTAG, "Invalid SRES/Kc tuple returned from SIM", ex);
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            try {
                MessageDigest sha1 = MessageDigest.getInstance(mMasterKeyGenerationAlg);
                generateAndPersistKeys(sha1, new Fips186_2Prf(), randChallengeResults);
            } catch (NoSuchAlgorithmException | BufferUnderflowException ex) {
                LOG.e(mTAG, "Error while creating keys", ex);
                return buildClientErrorResponse(message.eapIdentifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            try {
                mMacAlgorithm = Mac.getInstance(mMacAlgorithmString);
                mMacAlgorithm.init(new SecretKeySpec(mKAut, mMacAlgorithmString));

                byte[] mac = getMac(
                        message.eapCode,
                        message.eapIdentifier,
                        eapSimTypeData,
                        mNonce);
                // attributes are 'valid', so must have AtMac
                AtMac atMac = (AtMac) eapSimTypeData.attributeMap.get(EAP_AT_MAC);
                if (!Arrays.equals(mac, atMac.mac)) {
                    // MAC in message != calculated mac
                    LOG.e(mTAG, "Received message with invalid Mac."
                            + " expected=" + Arrays.toString(mac)
                            + ", actual=" + Arrays.toString(atMac.mac));
                    return buildClientErrorResponse(message.eapIdentifier,
                            AtClientErrorCode.UNABLE_TO_PROCESS);
                }
            } catch (GeneralSecurityException | EapSilentException
                    | EapSimAkaInvalidAttributeException ex) {
                // if the MAC can't be generated, we can't continue
                LOG.e(mTAG, "Error computing MAC for EapMessage", ex);
                return new EapError(ex);
            }

            ByteBuffer sresValues =
                    ByteBuffer.allocate(randChallengeResults.size() * mSresLenBytes);
            for (RandChallengeResult result : randChallengeResults) {
                sresValues.put(result.sres);
            }

            // server has been authenticated, so we can send a response
            return buildResponseMessageWithMac(
                    message.eapIdentifier,
                    EAP_SIM_CHALLENGE,
                    sresValues.array());
        }

        /**
         * Returns true iff the given EapSimTypeData contains both AT_RAND and AT_MAC attributes.
         */
        @VisibleForTesting
        boolean isValidChallengeAttributes(EapSimTypeData eapSimTypeData) {
            Set<Integer> attrs = eapSimTypeData.attributeMap.keySet();
            return attrs.contains(EAP_AT_RAND) && attrs.contains(EAP_AT_MAC);
        }

        @VisibleForTesting
        List<RandChallengeResult> getRandChallengeResults(EapSimTypeData eapSimTypeData)
                throws EapSimInvalidLengthException {
            AtRandSim atRand = (AtRandSim) eapSimTypeData.attributeMap.get(EAP_AT_RAND);
            List<byte[]> randList = atRand.rands;
            List<RandChallengeResult> challengeResults = new ArrayList<>();

            for (byte[] rand : randList) {
                // Rand (pre-Base64 formatting) needs to be formatted as [length][rand data]
                ByteBuffer formattedRand = ByteBuffer.allocate(rand.length + 1);
                formattedRand.put((byte) rand.length);
                formattedRand.put(rand);

                String base64Challenge =
                        Base64.encodeToString(formattedRand.array(), Base64.NO_WRAP);
                String challengeResponse = mTelephonyManager.getIccAuthentication(
                        mEapSimConfig.apptype,
                        TelephonyManager.AUTHTYPE_EAP_SIM,
                        base64Challenge);
                byte[] challengeResponseBytes = Base64.decode(challengeResponse, Base64.DEFAULT);

                RandChallengeResult randChallengeResult =
                        getRandChallengeResultFromResponse(challengeResponseBytes);
                challengeResults.add(randChallengeResult);

                // Log rand/challenge as PII
                LOG.d(mTAG,
                        "rand=" + LOG.pii(rand)
                        + " SRES=" + LOG.pii(randChallengeResult.sres)
                        + " Kc=" + LOG.pii(randChallengeResult.kc));
            }

            return challengeResults;
        }

        /**
         * Parses the SRES and Kc values from the given challengeResponse. The values are returned
         * in a Pair<byte[], byte[]>, where SRES and Kc are the first and second values,
         * respectively.
         */
        @VisibleForTesting
        RandChallengeResult getRandChallengeResultFromResponse(byte[] challengeResponse)
                throws EapSimInvalidLengthException {
            ByteBuffer buffer = ByteBuffer.wrap(challengeResponse);
            int lenSres = Byte.toUnsignedInt(buffer.get());
            if (lenSres != mSresLenBytes) {
                throw new EapSimInvalidLengthException("Invalid SRES length specified");
            }
            byte[] sres = new byte[mSresLenBytes];
            buffer.get(sres);

            int lenKc = Byte.toUnsignedInt(buffer.get());
            if (lenKc != mKcLenBytes) {
                throw new EapSimInvalidLengthException("Invalid Kc length specified");
            }
            byte[] kc = new byte[mKcLenBytes];
            buffer.get(kc);

            return new RandChallengeResult(sres, kc);
        }

        @VisibleForTesting
        class RandChallengeResult {
            public final byte[] sres;
            public final byte[] kc;

            RandChallengeResult(byte[] sres, byte[] kc) throws EapSimInvalidLengthException {
                this.sres = sres;
                this.kc = kc;

                if (sres.length != mSresLenBytes) {
                    throw new EapSimInvalidLengthException("Invalid SRES length");
                }
                if (kc.length != mKcLenBytes) {
                    throw new EapSimInvalidLengthException("Invalid Kc length");
                }
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof RandChallengeResult)) return false;
                RandChallengeResult that = (RandChallengeResult) o;
                return Arrays.equals(sres, that.sres)
                        && Arrays.equals(kc, that.kc);
            }

            @Override
            public int hashCode() {
                int result = Arrays.hashCode(sres);
                result = 31 * result + Arrays.hashCode(kc);
                return result;
            }
        }

        @VisibleForTesting
        void generateAndPersistKeys(
                MessageDigest messageDigest,
                Fips186_2Prf prf,
                List<RandChallengeResult> randChallengeResults) {
            int numInputBytes =
                    mIdentity.length
                    + (randChallengeResults.size() * mKcLenBytes)
                    + mNonce.length
                    + (mVersions.size() * mBytesPerShort) // 2B per version
                    + mVersionLenBytes;

            ByteBuffer mkInputBuffer = ByteBuffer.allocate(numInputBytes);
            mkInputBuffer.put(mIdentity);
            for (RandChallengeResult randChallengeResult : randChallengeResults) {
                mkInputBuffer.put(randChallengeResult.kc);
            }
            mkInputBuffer.put(mNonce);
            for (int i : mVersions) {
                mkInputBuffer.putShort((short) i);
            }
            mkInputBuffer.putShort((short) AtSelectedVersion.SUPPORTED_VERSION);

            byte[] mk = messageDigest.digest(mkInputBuffer.array());

            // run mk through FIPS 186-2
            int outputBytes = mKEncr.length + mKAut.length + mMsk.length + mEmsk.length;
            byte[] prfResult = prf.getRandom(mk, outputBytes);

            ByteBuffer mkResultBuffer = ByteBuffer.wrap(prfResult);
            mkResultBuffer.get(mKEncr);
            mkResultBuffer.get(mKAut);
            mkResultBuffer.get(mMsk);
            mkResultBuffer.get(mEmsk);

            // Log keys as PII
            LOG.d(mTAG, "K_encr=" + LOG.pii(mKEncr));
            LOG.d(mTAG, "K_aut=" + LOG.pii(mKAut));
            LOG.d(mTAG, "MSK=" + LOG.pii(mMsk));
            LOG.d(mTAG, "EMSK=" + LOG.pii(mEmsk));
        }
    }

    protected class FinalState extends EapSimState {
        @Override
        public EapResult process(EapMessage msg) {
            return new EapError(
                    new IllegalStateException("Attempting to process from a FinalState"));
        }
    }

    private EapResult handleEapNotification(String tag, EapMessage message) {
        // Type-Data will be UTF-8 encoded ISO 10646 characters (RFC 3748 Section 5.2)
        String content = new String(message.eapData.eapTypeData, StandardCharsets.UTF_8);
        LOG.i(tag, "Received EAP-Request/Notification: [" + content + "]");
        return EapMessage.getNotificationResponse(message.eapIdentifier);
    }

    @VisibleForTesting
    EapResult buildResponseMessage(int subtype, int identifier,
            List<EapSimAkaAttribute> eapSimAkaAttributes) {
        EapSimTypeData eapSimTypeData = new EapSimTypeData(subtype, eapSimAkaAttributes);
        EapData eapData = new EapData(EAP_TYPE_SIM, eapSimTypeData.encode());

        try {
            EapMessage eapMessage = new EapMessage(EAP_CODE_RESPONSE, identifier, eapData);
            return EapResponse.getEapResponse(eapMessage);
        } catch (EapSilentException ex) {
            return new EapError(ex);
        }
    }

    @VisibleForTesting
    EapResult buildClientErrorResponse(int identifier, AtClientErrorCode clientErrorCode) {
        EapSimTypeData eapSimTypeData = new EapSimTypeData(
                EAP_SIM_CLIENT_ERROR, Arrays.asList(clientErrorCode));
        byte[] encodedTypeData = eapSimTypeData.encode();

        EapData eapData = new EapData(EAP_TYPE_SIM, encodedTypeData);
        try {
            EapMessage response = new EapMessage(EAP_CODE_RESPONSE, identifier, eapData);
            return EapResponse.getEapResponse(response);
        } catch (EapSilentException ex) {
            return new EapError(ex);
        }
    }

    @VisibleForTesting
    byte[] getMac(
            int eapCode,
            int eapIdentifier,
            EapSimTypeData eapSimTypeData,
            byte[] extraData) throws EapSimAkaInvalidAttributeException, EapSilentException {
        if (mMacAlgorithm == null) {
            throw new IllegalStateException(
                    "Can't calculate MAC before mMacAlgorithm is set in ChallengeState");
        }

        // cache original Mac so it can be restored after calculating the Mac
        AtMac originalMac = (AtMac) eapSimTypeData.attributeMap.get(EAP_AT_MAC);
        eapSimTypeData.attributeMap.put(EAP_AT_MAC, new AtMac());

        byte[] typeDataWithEmptyMac = eapSimTypeData.encode();
        EapData eapData = new EapData(EAP_TYPE_SIM, typeDataWithEmptyMac);
        EapMessage messageForMac = new EapMessage(eapCode, eapIdentifier, eapData);

        ByteBuffer buffer =
                ByteBuffer.allocate(messageForMac.eapLength + extraData.length);
        buffer.put(messageForMac.encode());
        buffer.put(extraData);
        byte[] mac = mMacAlgorithm.doFinal(buffer.array());

        eapSimTypeData.attributeMap.put(EAP_AT_MAC, originalMac);

        // need HMAC-SHA1-128 - first 16 bytes of SHA1 (RFC 4186 Section 10.14)
        return Arrays.copyOfRange(mac, 0, AtMac.MAC_LENGTH);
    }

    @VisibleForTesting
    EapResult buildResponseMessageWithMac(
            int identifier,
            int eapSubtype,
            byte[] extraData) {
        try {
            EapSimTypeData eapSimTypeData =
                    new EapSimTypeData(eapSubtype, Arrays.asList(new AtMac()));

            byte[] mac = getMac(
                    EAP_CODE_RESPONSE,
                    identifier,
                    eapSimTypeData,
                    extraData);

            eapSimTypeData.attributeMap.put(EAP_AT_MAC, new AtMac(mac));
            EapData eapData = new EapData(EAP_TYPE_SIM, eapSimTypeData.encode());
            EapMessage eapMessage = new EapMessage(EAP_CODE_RESPONSE, identifier, eapData);
            return EapResponse.getEapResponse(eapMessage);
        } catch (EapSimAkaInvalidAttributeException | EapSilentException ex) {
            // this should never happen
            return new EapError(ex);
        }
    }

    @VisibleForTesting
    EapResult handleEapSimNotification(
            boolean isPreChallengeState,
            int identifier,
            EapSimTypeData eapSimTypeData) {
        // EAP-SIM exchanges must not include more than one EAP-SIM notification round
        // (RFC 4186#6.1)
        if (mHasReceivedSimNotification) {
            return new EapError(
                    new EapInvalidRequestException("Received multiple EAP-SIM notifications"));
        }

        mHasReceivedSimNotification = true;
        AtNotification atNotification = (AtNotification)
                eapSimTypeData.attributeMap.get(EAP_AT_NOTIFICATION);

        // P bit of notification code is only allowed after a successful challenge round. This is
        // only possible in the ChallengeState (RFC 4186#6.1)
        if (isPreChallengeState && !atNotification.isPreSuccessfulChallenge) {
            return buildClientErrorResponse(identifier, AtClientErrorCode.UNABLE_TO_PROCESS);
        }

        if (atNotification.isPreSuccessfulChallenge) {
            // AT_MAC attribute must not be included when the P bit is set (RFC 4186#9.8)
            if (eapSimTypeData.attributeMap.containsKey(EAP_AT_MAC)) {
                return buildClientErrorResponse(identifier, AtClientErrorCode.UNABLE_TO_PROCESS);
            }

            return buildResponseMessage(EAP_SIM_NOTIFICATION, identifier, Arrays.asList());
        } else if (!eapSimTypeData.attributeMap.containsKey(EAP_AT_MAC)) {
            // MAC must be included for messages with their P bit not set (RFC 4186#9.8)
            return buildClientErrorResponse(
                    identifier,
                    AtClientErrorCode.UNABLE_TO_PROCESS);
        }

        try {
            byte[] mac = getMac(
                    EAP_CODE_REQUEST,
                    identifier,
                    eapSimTypeData,
                    new byte[0]);

            AtMac atMac = (AtMac) eapSimTypeData.attributeMap.get(EAP_AT_MAC);
            if (!Arrays.equals(mac, atMac.mac)) {
                // MAC in message != calculated mac
                return buildClientErrorResponse(identifier,
                        AtClientErrorCode.UNABLE_TO_PROCESS);
            }
        } catch (EapSilentException | EapSimAkaInvalidAttributeException ex) {
            // We can't continue if the MAC can't be generated
            return new EapError(ex);
        }

        // server has been authenticated, so we can send a response
        return buildResponseMessageWithMac(
                identifier,
                EAP_SIM_NOTIFICATION,
                new byte[0]);
    }
}
