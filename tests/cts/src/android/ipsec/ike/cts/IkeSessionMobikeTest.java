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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import android.net.ipsec.ike.IkeSession;
import android.net.ipsec.ike.IkeSessionConfiguration;
import android.net.ipsec.ike.IkeSessionParams;
import android.platform.test.annotations.AppModeFull;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.InetAddress;

@RunWith(AndroidJUnit4.class)
@AppModeFull(reason = "MANAGE_IPSEC_TUNNELS permission can't be granted to instant apps")
public class IkeSessionMobikeTest extends IkeSessionPskTestBase {
    private TunNetworkContext mSecondaryTunNetworkContext;

    private InetAddress mSecondaryLocalAddr;

    private IkeSession mIkeSession;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        mSecondaryLocalAddr = getNextAvailableIpv4AddressLocal();

        mSecondaryTunNetworkContext = new TunNetworkContext(mSecondaryLocalAddr);
    }

    @After
    public void tearDown() throws Exception {
        mSecondaryTunNetworkContext.tearDown();

        if (mIkeSession != null) {
            mIkeSession.kill();
        }

        super.tearDown();
    }

    @Override
    protected IkeSessionParams getIkeSessionParams(InetAddress remoteAddress) {
        return createIkeParamsBuilderBase(remoteAddress)
                .addIkeOption(IkeSessionParams.IKE_OPTION_MOBIKE)
                .build();
    }

    @Test
    public void testSetNetworkWithoutMobikeEnabled() throws Exception {
        if (!hasTunnelsFeature()) return;

        final String ikeInitResp =
                "46B8ECA1E0D72A18B45427679F9245D421202220000000000000015022000030"
                        + "0000002C010100040300000C0100000C800E0080030000080300000203000008"
                        + "0200000200000008040000022800008800020000A7AA3435D088EC1A2B7C2A47"
                        + "1FA1B85F1066C9B2006E7C353FB5B5FDBC2A88347ED2C6F5B7A265D03AE34039"
                        + "6AAC0145CFCC93F8BDB219DDFF22A603B8856A5DC59B6FAB7F17C5660CF38670"
                        + "8794FC72F273ADEB7A4F316519794AED6F8AB61F95DFB360FAF18C6C8CABE471"
                        + "6E18FE215348C2E582171A57FC41146B16C4AFE429000024A634B61C0E5C90C6"
                        + "8D8818B0955B125A9B1DF47BBD18775710792E651083105C2900001C00004004"
                        + "406FA3C5685A16B9B72C7F2EEE9993462C619ABE2900001C00004005AF905A87"
                        + "0A32222AA284A7070585601208A282F0290000080000402E290000100000402F"
                        + "00020003000400050000000800004014";
        final String IkeAuthRespWithoutMobikeSupport =
                "46B8ECA1E0D72A18B45427679F9245D42E20232000000001000000EC240000D0"
                        + "0D06D37198F3F0962DE8170D66F1A9008267F98CDD956D984BDCED2FC7FAF84A"
                        + "A6664EF25049B46B93C9ED420488E0C172AA6635BF4011C49792EF2B88FE7190"
                        + "E8859FEEF51724FD20C46E7B9A9C3DC4708EF7005707A18AB747C903ABCEAC5C"
                        + "6ECF5A5FC13633DCE3844A920ED10EF202F115DBFBB5D6D2D7AB1F34EB08DE7C"
                        + "A54DCE0A3A582753345CA2D05A0EFDB9DC61E81B2483B7D13EEE0A815D37252C"
                        + "23D2F29E9C30658227D2BB0C9E1A481EAA80BC6BE9006BEDC13E925A755A0290"
                        + "AEC4164D29997F52ED7DCC2E";

        // Open IKE Session
        mIkeSession = openIkeSessionWithTunnelModeChild(mRemoteAddress);
        performSetupIkeAndFirstChildBlocking(ikeInitResp, IkeAuthRespWithoutMobikeSupport);

        verifyIkeSessionSetupBlocking();

        final IkeSessionConfiguration ikeConfig = mIkeSessionCallback.awaitIkeConfig();
        assertFalse(ikeConfig.isIkeExtensionEnabled(IkeSessionConfiguration.EXTENSION_TYPE_MOBIKE));

        try {
            // manually change network when MOBIKE is not enabled
            mIkeSession.setNetwork(mSecondaryTunNetworkContext.tunNetwork);

            fail("Expected error for setNetwork() without MOBIKE enabled");
        } catch (IllegalStateException expected) {
        }
    }

    /** The MOBIKE spec explicitly disallows Transport mode. */
    @Test(expected = IllegalArgumentException.class)
    public void testStartSessionWithMobikeAndTransportMode() {
        mIkeSession = openIkeSessionWithTransportModeChild(mRemoteAddress);
    }
}
