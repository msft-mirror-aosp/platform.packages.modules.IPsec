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

package android.ipsec.ike.cts;

import static android.net.ipsec.ike.IkeSessionConfiguration.EXTENSION_TYPE_FRAGMENTATION;
import static android.net.ipsec.ike.IkeSessionConfiguration.EXTENSION_TYPE_MOBIKE;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.net.Network;
import android.net.ipsec.ike.IkeSessionConfiguration;
import android.net.ipsec.ike.IkeSessionConnectionInfo;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
public class SessionConfigurationTest extends IkeTestNetworkBase {
    private static final byte[] REMOTE_VENDOR_ID_1 = "REMOTE_VENDOR_ID_1".getBytes();
    private static final byte[] REMOTE_VENDOR_ID_2 = "REMOTE_VENDOR_ID_2".getBytes();
    private static final String REMOTE_APP_VERSION = "REMOTE_APP_VERSION";
    private static final String REMOTE_APP_VERSION_NONE = "";

    private interface IkeSessionConnectionInfoTestRunner {
        void run(IkeSessionConnectionInfo connectionInfo, Network network) throws Exception;
    }

    private void runTestWithIkeSessionConnectionInfo(IkeSessionConnectionInfoTestRunner testRunner)
            throws Exception {
        try (TunNetworkContext tunNwContext = new TunNetworkContext(IPV6_ADDRESS_LOCAL)) {
            final IkeSessionConnectionInfo connectionInfo =
                    new IkeSessionConnectionInfo(
                            IPV6_ADDRESS_LOCAL, IPV6_ADDRESS_REMOTE, tunNwContext.tunNetwork);
            testRunner.run(connectionInfo, tunNwContext.tunNetwork);
        }
    }

    @Test
    public void testIkeConnectionInfo() throws Exception {
        runTestWithIkeSessionConnectionInfo(
                (connectionInfo, network) -> {
                    assertEquals(IPV6_ADDRESS_LOCAL, connectionInfo.getLocalAddress());
                    assertEquals(IPV6_ADDRESS_REMOTE, connectionInfo.getRemoteAddress());
                    assertEquals(network, connectionInfo.getNetwork());
                });
    }

    private void addToIkeSessionConfigBuilder(IkeSessionConfiguration.Builder builder) {
        builder.addIkeExtension(EXTENSION_TYPE_FRAGMENTATION)
                .addIkeExtension(EXTENSION_TYPE_MOBIKE)
                .addPcscfServer(PCSCF_IPV4_ADDRESS_1)
                .addPcscfServer(PCSCF_IPV6_ADDRESS_1)
                .addRemoteVendorId(REMOTE_VENDOR_ID_1)
                .addRemoteVendorId(REMOTE_VENDOR_ID_2)
                .setRemoteApplicationVersion(REMOTE_APP_VERSION);
    }

    @Test
    public void testIkeSessionConfiguration() throws Exception {
        runTestWithIkeSessionConnectionInfo(
                (connectionInfo, network) -> {
                    final IkeSessionConfiguration.Builder builder =
                            new IkeSessionConfiguration.Builder(connectionInfo);
                    addToIkeSessionConfigBuilder(builder);
                    final IkeSessionConfiguration config = builder.build();

                    assertEquals(connectionInfo, config.getIkeSessionConnectionInfo());
                    assertTrue(config.isIkeExtensionEnabled(EXTENSION_TYPE_FRAGMENTATION));
                    assertTrue(config.isIkeExtensionEnabled(EXTENSION_TYPE_MOBIKE));
                    assertEquals(
                            Arrays.asList(PCSCF_IPV4_ADDRESS_1, PCSCF_IPV6_ADDRESS_1),
                            config.getPcscfServers());
                    assertEquals(
                            Arrays.asList(REMOTE_VENDOR_ID_1, REMOTE_VENDOR_ID_2),
                            config.getRemoteVendorIds());
                    assertEquals(REMOTE_APP_VERSION, config.getRemoteApplicationVersion());
                });
    }

    @Test
    public void testIkeSessionConfigurationClearMethods() throws Exception {
        runTestWithIkeSessionConnectionInfo(
                (connectionInfo, network) -> {
                    final IkeSessionConfiguration.Builder builder =
                            new IkeSessionConfiguration.Builder(connectionInfo);
                    addToIkeSessionConfigBuilder(builder);
                    final IkeSessionConfiguration config =
                            builder.clearIkeExtensions()
                                    .clearPcscfServers()
                                    .clearRemoteVendorIds()
                                    .clearRemoteApplicationVersion()
                                    .build();

                    assertEquals(connectionInfo, config.getIkeSessionConnectionInfo());
                    assertFalse(config.isIkeExtensionEnabled(EXTENSION_TYPE_FRAGMENTATION));
                    assertFalse(config.isIkeExtensionEnabled(EXTENSION_TYPE_MOBIKE));
                    assertTrue(config.getPcscfServers().isEmpty());
                    assertTrue(config.getRemoteVendorIds().isEmpty());
                    assertEquals(REMOTE_APP_VERSION_NONE, config.getRemoteApplicationVersion());
                });
    }
}
