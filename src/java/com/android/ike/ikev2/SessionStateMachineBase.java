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

import static com.android.ike.ikev2.IkeManager.getIkeLog;

import android.os.Looper;

import com.android.internal.util.StateMachine;

/**
 * This class represents the common information of both IkeSessionStateMachine and
 * ChildSessionStateMachine
 */
abstract class SessionStateMachineBase extends StateMachine {
    private final String mLogTag;

    protected SessionStateMachineBase(String name, Looper looper) {
        super(name, looper);
        mLogTag = name;
    }

    @Override
    protected void log(String s) {
        getIkeLog().d(mLogTag, s);
    }

    @Override
    protected void logd(String s) {
        getIkeLog().d(mLogTag, s);
    }

    protected void logd(String s, Throwable e) {
        getIkeLog().d(mLogTag, s, e);
    }

    @Override
    protected void logv(String s) {
        getIkeLog().v(mLogTag, s);
    }

    @Override
    protected void logi(String s) {
        getIkeLog().i(mLogTag, s);
    }

    protected void logi(String s, Throwable cause) {
        getIkeLog().i(mLogTag, s, cause);
    }

    @Override
    protected void logw(String s) {
        getIkeLog().w(mLogTag, s);
    }

    @Override
    protected void loge(String s) {
        getIkeLog().e(mLogTag, s);
    }

    @Override
    protected void loge(String s, Throwable e) {
        getIkeLog().e(mLogTag, s, e);
    }

    protected void logWtf(String s) {
        getIkeLog().wtf(mLogTag, s);
    }

    protected void logWtf(String s, Throwable e) {
        getIkeLog().wtf(mLogTag, s, e);
    }
}
