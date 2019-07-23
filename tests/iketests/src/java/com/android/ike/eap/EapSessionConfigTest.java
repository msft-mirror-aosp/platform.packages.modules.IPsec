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

import static com.android.ike.eap.message.EapData.EAP_TYPE_SIM;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.android.ike.eap.EapSessionConfig.EapMethodConfig;
import com.android.ike.eap.EapSessionConfig.EapSimConfig;

import org.junit.Test;

public class EapSessionConfigTest {
    private static final byte[] EAP_IDENTITY = "test@android.net".getBytes();
    private static final int SUB_ID = 1;

    @Test
    public void testBuild() {
        EapSessionConfig result = new EapSessionConfig.Builder()
                .setEapIdentity(EAP_IDENTITY)
                .setEapSimConfig(SUB_ID)
                .build();

        assertArrayEquals(EAP_IDENTITY, result.eapIdentity);

        EapMethodConfig eapMethodConfig = result.eapConfigs.get(EAP_TYPE_SIM);
        assertEquals(EAP_TYPE_SIM, eapMethodConfig.methodType);
        assertTrue(eapMethodConfig instanceof EapSimConfig);
    }
}
