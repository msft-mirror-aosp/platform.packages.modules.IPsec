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

package com.android.ike.eap;

import static android.telephony.TelephonyManager.APPTYPE_USIM;

import static com.android.ike.eap.EapSessionConfig.DEFAULT_IDENTITY;
import static com.android.ike.eap.message.EapData.EAP_TYPE_AKA;
import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.android.ike.eap.EapSessionConfig.EapAkaConfig;
import com.android.ike.eap.EapSessionConfig.EapMethodConfig;
import com.android.ike.eap.EapSessionConfig.EapSimConfig;

import org.junit.Test;

public class EapSessionConfigTest {
    private static final byte[] EAP_IDENTITY = "test@android.net".getBytes();
    private static final int SUB_ID = 1;

    @Test
    public void testBuildEapSim() {
        EapSessionConfig result = new EapSessionConfig.Builder()
                .setEapIdentity(EAP_IDENTITY)
                .setEapSimConfig(SUB_ID, APPTYPE_USIM)
                .build();

        assertArrayEquals(EAP_IDENTITY, result.eapIdentity);

        EapMethodConfig eapMethodConfig = result.eapConfigs.get(EAP_TYPE_SIM);
        assertEquals(EAP_TYPE_SIM, eapMethodConfig.methodType);
        EapSimConfig eapSimConfig = (EapSimConfig) eapMethodConfig;
        assertEquals(SUB_ID, eapSimConfig.subId);
        assertEquals(APPTYPE_USIM, eapSimConfig.apptype);
    }

    @Test
    public void testBuildEapAka() {
        EapSessionConfig result = new EapSessionConfig.Builder()
                .setEapAkaConfig(SUB_ID, APPTYPE_USIM)
                .build();

        assertArrayEquals(DEFAULT_IDENTITY, result.eapIdentity);
        EapMethodConfig eapMethodConfig = result.eapConfigs.get(EAP_TYPE_AKA);
        EapAkaConfig eapAkaConfig = (EapAkaConfig) eapMethodConfig;
        assertEquals(SUB_ID, eapAkaConfig.subId);
        assertEquals(APPTYPE_USIM, eapAkaConfig.apptype);
    }

    @Test
    public void testBuildWithoutConfigs() {
        try {
            new EapSessionConfig.Builder().build();
            fail("build() should throw an IllegalStateException if no EAP methods are configured");
        } catch (IllegalStateException expected) {
        }
    }
}
