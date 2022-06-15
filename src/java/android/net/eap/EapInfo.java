/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.net.eap;

import static android.net.eap.EapSessionConfig.EapMethodConfig.EapMethod;

/**
 * EapInfo represents a container for EAP information from a server during Authentication.
 *
 * @hide
 */
public abstract class EapInfo {
    /** @hide */
    private final int mEapMethodType;

    /** @hide */
    public EapInfo(@EapMethod int eapMethodType) {
        mEapMethodType = eapMethodType;
    }

    /**
     * Retrieves EAP method type
     *
     * @return EAP method type
     * @hide
     */
    public int getEapMethodType() {
        return mEapMethodType;
    }
}
