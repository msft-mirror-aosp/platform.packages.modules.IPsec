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

package android.net.ipsec.ike;

import android.annotation.IntDef;
import android.annotation.NonNull;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** IkeSessionConfiguration represents the negotiated configuration for a IKE Session. */
public final class IkeSessionConfiguration {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({EXTENSION_TYPE_FRAGMENTATION, EXTENSION_TYPE_MOBIKE})
    public @interface ExtensionType {}

    public static final int EXTENSION_TYPE_FRAGMENTATION = 1;
    public static final int EXTENSION_TYPE_MOBIKE = 2;

    /**
     * Gets remote(server) version information.
     *
     * @return application version of the remote server, or empty string if the remote server did
     *     not provide the application version
     */
    @NonNull
    public String getRemoteApplicationVersion() {
        return "";
    }

    /**
     * Checks if an IKE extension is enabled.
     *
     * <p>An IKE extension is enabled when both sides can support it. This negotiation always
     * happens in IKE initial changes(IKE INIT and IKE AUTH).
     *
     * @param extensionType the extension type
     * @return {@code true} if this extension is enabled
     */
    public boolean isIkeExtensionEnabled(@ExtensionType int extensionType) {
        return false;
    }

    // TODO: Implement IkeSessionConfiguration.
}
