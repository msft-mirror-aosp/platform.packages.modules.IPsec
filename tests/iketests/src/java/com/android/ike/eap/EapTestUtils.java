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

import java.util.HashMap;

/**
 * EapTestUtils is a util class for providing test-values of EAP-related objects.
 */
public class EapTestUtils {
    /**
     * Creates and returns a dummy EapSessionConfig instance.
     *
     * @return a new, empty EapSessionConfig instance
     */
    public static EapSessionConfig getDummyEapSessionConfig() {
        return new EapSessionConfig(new HashMap<>(), new byte[0]);
    }
}
