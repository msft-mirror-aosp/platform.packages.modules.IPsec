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

package com.android.ike.ikev2;

import android.content.Context;
import android.net.IpSecManager;
import android.os.Looper;

import com.android.ike.ikev2.crypto.IkeMacPrf;
import com.android.internal.annotations.VisibleForTesting;

import java.net.InetAddress;

/** Package private factory for making ChildSessionStateMachine. */
// TODO: Make it a inner Creator class of ChildSessionStateMachine
final class ChildSessionStateMachineFactory {

    private static IChildSessionFactoryHelper sChildSessionHelper = new ChildSessionFactoryHelper();

    /** Package private. */
    static ChildSessionStateMachine makeChildSessionStateMachine(
            String name,
            Looper looper,
            Context context,
            ChildSessionOptions sessionOptions,
            InetAddress localAddress,
            InetAddress remoteAddress,
            IkeMacPrf prf,
            byte[] skD) {
        return sChildSessionHelper.makeChildSessionStateMachine(
                name, looper, context, sessionOptions, localAddress, remoteAddress, prf, skD);
    }

    @VisibleForTesting
    static void setChildSessionFactoryHelper(IChildSessionFactoryHelper helper) {
        sChildSessionHelper = helper;
    }

    /**
     * IChildSessionFactoryHelper provides a package private interface for constructing
     * ChildSessionStateMachine.
     *
     * <p>IChildSessionFactoryHelper exists so that the interface is injectable for testing.
     */
    interface IChildSessionFactoryHelper {
        ChildSessionStateMachine makeChildSessionStateMachine(
                String name,
                Looper looper,
                Context context,
                ChildSessionOptions sessionOptions,
                InetAddress localAddress,
                InetAddress remoteAddress,
                IkeMacPrf prf,
                byte[] skD);
    }

    /**
     * ChildSessionFactoryHelper implements a method for constructing ChildSessionStateMachine.
     *
     * <p>Package private.
     */
    static class ChildSessionFactoryHelper implements IChildSessionFactoryHelper {
        public ChildSessionStateMachine makeChildSessionStateMachine(
                String name,
                Looper looper,
                Context context,
                ChildSessionOptions sessionOptions,
                InetAddress localAddress,
                InetAddress remoteAddress,
                IkeMacPrf prf,
                byte[] skD) {
            ChildSessionStateMachine childSession =
                    new ChildSessionStateMachine(
                            name,
                            looper,
                            context,
                            (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE),
                            sessionOptions,
                            localAddress,
                            remoteAddress,
                            prf,
                            skD);
            childSession.start();
            return childSession;
        }
    }
}
