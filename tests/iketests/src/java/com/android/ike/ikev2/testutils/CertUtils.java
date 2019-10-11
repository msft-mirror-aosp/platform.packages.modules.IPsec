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

package com.android.ike.ikev2.testutils;

import android.content.Context;

import androidx.test.InstrumentationRegistry;

import com.android.ike.ikev2.message.IkeMessage;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** CertUtils provides utility methods for creating X509 certificate. */
public final class CertUtils {
    private static final String PEM_FOLDER_NAME = "pem";

    /** Creates an X509Certificate with a pem file */
    public static X509Certificate createCertFromPemFile(String fileName) throws Exception {
        Context context = InstrumentationRegistry.getContext();
        InputStream inputStream =
                context.getResources().getAssets().open(PEM_FOLDER_NAME + "/" + fileName);

        CertificateFactory factory =
                CertificateFactory.getInstance("X.509", IkeMessage.getSecurityProvider());
        return (X509Certificate) factory.generateCertificate(inputStream);
    }
}
