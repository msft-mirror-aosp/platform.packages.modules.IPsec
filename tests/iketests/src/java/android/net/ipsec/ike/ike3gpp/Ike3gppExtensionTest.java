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

package android.net.ipsec.ike.ike3gpp;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

import android.net.ipsec.ike.ike3gpp.Ike3gppExtension.Ike3gppCallback;

import org.junit.Before;
import org.junit.Test;

public class Ike3gppExtensionTest {
    private Ike3gppCallback mMockIke3gppCallback;
    private Ike3gppParams mIke3gppParams;

    @Before
    public void setUp() {
        mMockIke3gppCallback = mock(Ike3gppCallback.class);
        mIke3gppParams = new Ike3gppParams.Builder().build();
    }

    @Test
    public void testIke3gppExtensionConstructor() {
        Ike3gppExtension ike3gppExtension =
                new Ike3gppExtension(mIke3gppParams, mMockIke3gppCallback);

        assertEquals(mMockIke3gppCallback, ike3gppExtension.getIke3gppCallback());
        assertEquals(mIke3gppParams, ike3gppExtension.getIke3gppParams());
    }

    @Test(expected = NullPointerException.class)
    public void testIke3gppExtensionConstructorInvalidCallback() {
        Ike3gppExtension ike3gppExtension = new Ike3gppExtension(mIke3gppParams, null);
    }

    @Test(expected = NullPointerException.class)
    public void testIke3gppExtensionConstructorInvalidParams() {
        Ike3gppExtension ike3gppExtension = new Ike3gppExtension(null, mMockIke3gppCallback);
    }
}
