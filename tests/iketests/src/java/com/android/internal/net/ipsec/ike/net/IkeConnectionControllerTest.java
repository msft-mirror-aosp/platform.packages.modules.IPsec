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

package com.android.internal.net.ipsec.test.ike.net;

import static android.net.ipsec.test.ike.IkeSessionParams.IKE_OPTION_FORCE_PORT_4500;

import static com.android.internal.net.ipsec.test.ike.net.IkeConnectionController.NAT_TRAVERSAL_SUPPORTED;
import static com.android.internal.net.ipsec.test.ike.net.IkeConnectionController.NAT_TRAVERSAL_SUPPORT_NOT_CHECKED;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.net.ConnectivityManager.NetworkCallback;
import android.net.Network;
import android.net.ipsec.test.ike.IkeSessionParams;
import android.net.ipsec.test.ike.exceptions.IkeInternalException;
import android.os.Looper;

import com.android.internal.net.ipsec.test.ike.IkeContext;
import com.android.internal.net.ipsec.test.ike.IkeSessionTestBase;
import com.android.internal.net.ipsec.test.ike.utils.RandomnessFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;

public class IkeConnectionControllerTest extends IkeSessionTestBase {
    private IkeSessionParams mMockIkeParams;
    private IkeLocalAddressGenerator mMockIkeLocalAddressGenerator;
    private IkeConnectionController.Callback mMockConnectionCtrlCb;
    private Network mMockCallerConfiguredNetwork;

    private IkeContext mIkeContext;
    private IkeConnectionController mIkeConnectionCtrl;

    private void setupLocalAddressForNetwork(Network network, InetAddress address)
            throws Exception {
        boolean isIpv4 = address instanceof Inet4Address;
        when(mMockIkeLocalAddressGenerator.generateLocalAddress(
                        eq(network), eq(isIpv4), any(), anyInt()))
                .thenReturn(address);
    }

    private void setupRemoteAddressForNetwork(Network network, InetAddress address)
            throws Exception {
        doAnswer(
                new Answer() {
                    public Object answer(InvocationOnMock invocation) throws IOException {
                        return new InetAddress[] {address};
                    }
                })
                .when(network)
                .getAllByName(REMOTE_HOSTNAME);
    }

    private IkeConnectionController buildDefaultIkeConnectionCtrl() throws Exception {
        return new IkeConnectionController(
                new IkeConnectionController.Config(
                        mIkeContext,
                        mMockIkeParams,
                        mMockIkeLocalAddressGenerator,
                        mMockConnectionCtrlCb));
    }

    private IkeConnectionController buildIkeConnectionCtrlWithNetwork(Network callerConfiguredNw)
            throws Exception {
        when(mMockIkeParams.getConfiguredNetwork()).thenReturn(callerConfiguredNw);

        Network networkBeingUsed =
                callerConfiguredNw == null ? mMockDefaultNetwork : callerConfiguredNw;
        setupLocalAddressForNetwork(networkBeingUsed, LOCAL_ADDRESS);
        setupRemoteAddressForNetwork(networkBeingUsed, REMOTE_ADDRESS);

        return buildDefaultIkeConnectionCtrl();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        mIkeContext =
                new IkeContext(mock(Looper.class), mSpyContext, mock(RandomnessFactory.class));
        mMockIkeParams = mock(IkeSessionParams.class);
        mMockIkeLocalAddressGenerator = mock(IkeLocalAddressGenerator.class);
        mMockConnectionCtrlCb = mock(IkeConnectionController.Callback.class);
        mMockCallerConfiguredNetwork = mock(Network.class);

        when(mMockIkeParams.hasIkeOption(eq(IKE_OPTION_FORCE_PORT_4500))).thenReturn(false);
        when(mMockIkeParams.getServerHostname()).thenReturn(REMOTE_HOSTNAME);
        when(mMockIkeParams.getConfiguredNetwork()).thenReturn(null);

        setupLocalAddressForNetwork(mMockDefaultNetwork, LOCAL_ADDRESS);
        setupRemoteAddressForNetwork(mMockDefaultNetwork, REMOTE_ADDRESS);

        mIkeConnectionCtrl = buildDefaultIkeConnectionCtrl();
        mIkeConnectionCtrl.setUp();
    }

    @After
    public void tearDown() throws Exception {
        mIkeConnectionCtrl.tearDown();
    }

    private void verifySetupAndTeardownWithNw(Network callerConfiguredNw) throws Exception {
        mIkeConnectionCtrl.tearDown();
        mIkeConnectionCtrl = buildIkeConnectionCtrlWithNetwork(callerConfiguredNw);
        mIkeConnectionCtrl.setUp();

        Network expectedNetwork =
                callerConfiguredNw == null ? mMockDefaultNetwork : callerConfiguredNw;
        assertEquals(expectedNetwork, mIkeConnectionCtrl.getNetwork());
        assertEquals(LOCAL_ADDRESS, mIkeConnectionCtrl.getLocalAddress());
        assertEquals(REMOTE_ADDRESS, mIkeConnectionCtrl.getRemoteAddress());
        assertEquals(NAT_TRAVERSAL_SUPPORT_NOT_CHECKED, mIkeConnectionCtrl.getNatStatus());

        mIkeConnectionCtrl.tearDown();
        verify(mMockConnectManager, never()).unregisterNetworkCallback(any(NetworkCallback.class));
    }

    @Test
    public void testSetupAndTeardownWithDefaultNw() throws Exception {
        verifySetupAndTeardownWithNw(null /* callerConfiguredNw */);
    }

    @Test
    public void testSetupAndTeardownWithConfiguredNw() throws Exception {
        verifySetupAndTeardownWithNw(mMockCallerConfiguredNetwork);
    }

    @Test
    public void testSetSeverNattSupport() throws Exception {
        mIkeConnectionCtrl.setSeverNattSupport(true);

        assertEquals(NAT_TRAVERSAL_SUPPORTED, mIkeConnectionCtrl.getNatStatus());
    }

    private IkeNetworkCallbackBase enableMobilityAndReturnCb(boolean isDefaultNetwork)
            throws Exception {
        mIkeConnectionCtrl.enableMobility();

        ArgumentCaptor<IkeNetworkCallbackBase> networkCallbackCaptor =
                ArgumentCaptor.forClass(IkeNetworkCallbackBase.class);

        if (isDefaultNetwork) {
            verify(mMockConnectManager)
                    .registerDefaultNetworkCallback(networkCallbackCaptor.capture(), any());
        } else {
            verify(mMockConnectManager)
                    .registerNetworkCallback(any(), networkCallbackCaptor.capture(), any());
        }

        return networkCallbackCaptor.getValue();
    }

    @Test
    public void testEnableMobilityWithDefaultNw() throws Exception {
        IkeNetworkCallbackBase callback = enableMobilityAndReturnCb(true /* isDefaultNetwork */);

        assertEquals(mMockDefaultNetwork, callback.getNetwork());
        assertEquals(LOCAL_ADDRESS, callback.getAddress());
    }

    @Test
    public void testEnableMobilityWithConfiguredNw() throws Exception {
        mIkeConnectionCtrl.tearDown();
        mIkeConnectionCtrl = buildIkeConnectionCtrlWithNetwork(mMockCallerConfiguredNetwork);
        mIkeConnectionCtrl.setUp();

        IkeNetworkCallbackBase callback = enableMobilityAndReturnCb(false /* isDefaultNetwork */);
        assertEquals(mMockCallerConfiguredNetwork, callback.getNetwork());
        assertEquals(LOCAL_ADDRESS, callback.getAddress());
    }

    private void verifyNetworkAndAddressesAfterMobilityEvent(
            Network expectedNetwork,
            InetAddress expectedLocalAddress,
            InetAddress expectedRemoteAddress,
            IkeNetworkCallbackBase callback) {
        assertEquals(expectedNetwork, mIkeConnectionCtrl.getNetwork());
        assertEquals(UPDATED_LOCAL_ADDRESS, mIkeConnectionCtrl.getLocalAddress());
        assertEquals(expectedRemoteAddress, mIkeConnectionCtrl.getRemoteAddress());

        assertEquals(expectedNetwork, callback.getNetwork());
        assertEquals(expectedLocalAddress, callback.getAddress());
    }

    @Test
    public void testOnUnderlyingNetworkUpdatedWithNewNetwork() throws Exception {
        Network newNetwork = mock(Network.class);
        setupLocalAddressForNetwork(newNetwork, UPDATED_LOCAL_ADDRESS);
        setupRemoteAddressForNetwork(newNetwork, REMOTE_ADDRESS);

        IkeNetworkCallbackBase callback = enableMobilityAndReturnCb(true /* isDefaultNetwork */);
        mIkeConnectionCtrl.onUnderlyingNetworkUpdated(newNetwork);

        verifyNetworkAndAddressesAfterMobilityEvent(
                newNetwork, UPDATED_LOCAL_ADDRESS, REMOTE_ADDRESS, callback);
        verify(mMockConnectionCtrlCb).onUnderlyingNetworkUpdated(eq(true), eq(false));
    }

    @Test
    public void testOnUnderlyingNetworkUpdatedWithNewLp() throws Exception {
        reset(mMockDefaultNetwork);
        setupLocalAddressForNetwork(mMockDefaultNetwork, UPDATED_LOCAL_ADDRESS);
        setupRemoteAddressForNetwork(mMockDefaultNetwork, REMOTE_ADDRESS);

        IkeNetworkCallbackBase callback = enableMobilityAndReturnCb(true /* isDefaultNetwork */);
        mIkeConnectionCtrl.onUnderlyingNetworkUpdated(mMockDefaultNetwork);

        verifyNetworkAndAddressesAfterMobilityEvent(
                mMockDefaultNetwork, UPDATED_LOCAL_ADDRESS, REMOTE_ADDRESS, callback);
        verify(mMockConnectionCtrlCb).onUnderlyingNetworkUpdated(eq(false), eq(false));
    }

    @Test
    public void testOnUnderlyingNetworkUpdatedFail() throws Exception {
        IkeNetworkCallbackBase callback = enableMobilityAndReturnCb(true /* isDefaultNetwork */);
        mIkeConnectionCtrl.onUnderlyingNetworkUpdated(mock(Network.class));

        // Expected to fail due to DNS resolution failure
        verify(mMockConnectionCtrlCb).onError(any(IkeInternalException.class));
    }

    @Test
    public void testOnUnderlyingNetworkDied() throws Exception {
        mIkeConnectionCtrl.onUnderlyingNetworkDied();
        verify(mMockConnectionCtrlCb).onUnderlyingNetworkDied(eq(mMockDefaultNetwork));
    }
}
