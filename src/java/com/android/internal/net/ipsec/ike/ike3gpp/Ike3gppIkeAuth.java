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
package com.android.internal.net.ipsec.ike.ike3gpp;

import static android.net.ipsec.ike.IkeManager.getIkeLog;

import static com.android.internal.net.ipsec.ike.ike3gpp.Ike3gppExtensionExchange.NOTIFY_TYPE_N1_MODE_INFORMATION;

import android.annotation.NonNull;
import android.net.ipsec.ike.ike3gpp.Ike3gppExtension;
import android.net.ipsec.ike.ike3gpp.Ike3gppInfo;
import android.net.ipsec.ike.ike3gpp.Ike3gppN1ModeInformation;

import com.android.internal.net.ipsec.ike.exceptions.InvalidSyntaxException;
import com.android.internal.net.ipsec.ike.message.IkeNotifyPayload;
import com.android.internal.net.ipsec.ike.message.IkePayload;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * Ike3gppIkeAuth contains the implementation for IKE_AUTH 3GPP-specific functionality in IKEv2.
 *
 * <p>This class is package-private.
 */
class Ike3gppIkeAuth extends Ike3gppExchangeBase {
    private static final String TAG = Ike3gppIkeAuth.class.getSimpleName();

    /** Initializes an Ike3gppIkeAuth. */
    Ike3gppIkeAuth(@NonNull Ike3gppExtension ike3gppExtension, @NonNull Executor userCbExecutor) {
        super(ike3gppExtension, userCbExecutor);
    }

    List<IkePayload> getRequestPayloads() {
        List<IkePayload> ike3gppPayloads = new ArrayList<>();
        if (mIke3gppExtension.getIke3gppParams().hasPduSessionId()) {
            ike3gppPayloads.add(
                    Ike3gppN1ModeUtils.generateN1ModeCapabilityPayload(
                            mIke3gppExtension.getIke3gppParams().getPduSessionId()));
        }

        return ike3gppPayloads;
    }

    List<IkePayload> extract3gppResponsePayloads(List<IkePayload> payloads) {
        List<IkePayload> ike3gppPayloads = new ArrayList<>();

        for (IkePayload payload : payloads) {
            switch (payload.payloadType) {
                case IkePayload.PAYLOAD_TYPE_NOTIFY:
                    IkeNotifyPayload notifyPayload = (IkeNotifyPayload) payload;
                    if (notifyPayload.notifyType == NOTIFY_TYPE_N1_MODE_INFORMATION) {
                        ike3gppPayloads.add(notifyPayload);
                    }
                    break;
                default:
                    // not a 3GPP-specific payload
                    break;
            }
        }

        return ike3gppPayloads;
    }

    void handleAuthResp(List<IkePayload> ike3gppPayloads) throws InvalidSyntaxException {
        List<Ike3gppInfo> ike3gppInfos = new ArrayList<>();
        List<IkeNotifyPayload> notifyPayloads =
                IkePayload.getPayloadListForTypeInProvidedList(
                        IkePayload.PAYLOAD_TYPE_NOTIFY, IkeNotifyPayload.class, ike3gppPayloads);

        for (IkeNotifyPayload notifyPayload : notifyPayloads) {
            switch (notifyPayload.notifyType) {
                case NOTIFY_TYPE_N1_MODE_INFORMATION:
                    // N1_MODE_CAPABILITY must be configured for the client to be notified
                    if (!mIke3gppExtension.getIke3gppParams().hasPduSessionId()) {
                        getIkeLog()
                                .w(TAG, "Received N1_MODE_INFORMATION when N1 Mode is not enabled");
                        continue;
                    }

                    byte[] snssai =
                            Ike3gppN1ModeUtils.getSnssaiFromNotifyData(notifyPayload.notifyData);
                    ike3gppInfos.add(new Ike3gppN1ModeInformation(snssai));
                    break;
                default:
                    // non-3GPP payload. Can be ignored.
                    logd("Non-3GPP payload processed as 3GPP: " + notifyPayload.getTypeString());
                    break;
            }
        }

        maybeInvokeUserCallback(ike3gppInfos);
    }

    private void logd(String msg) {
        getIkeLog().d(TAG, msg);
    }
}
