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

package com.android.internal.net.ipsec.ike.utils;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Message;

/**
 * IkeAlarmReceiver represents a class that receives all the alarms set by IKE library
 *
 * <p>Alarm Manager holds a CPU wake lock as long as the alarm receiver's onReceive() method is
 * executing. Once onReceive() returns, the Alarm Manager releases this wake lock. Thus actions that
 * contain asynchronous process to complete might need acquire a wake lock later.
 */
public class IkeAlarmReceiver extends BroadcastReceiver {
    /** Broadcast intent action when the DPD alarm is fired */
    public static final String ACTION_FIRE_DPD = "IkeAlarmReceiver.FIRE_DPD";

    /** Parcelable name for DPD Message */
    public static final String PARCELABLE_NAME_DPD_MESSAGE =
            "IkeAlarmReceiver.PARCELABLE_NAME_DPD_MESSAGE";

    @Override
    public void onReceive(Context context, Intent intent) {
        final String action = intent.getAction();
        if (action.equals(ACTION_FIRE_DPD)) {
            Message message =
                    (Message) intent.getExtras().getParcelable(PARCELABLE_NAME_DPD_MESSAGE);

            // Use #dispatchMessage so that this method won't return util the message is processed
            message.getTarget().dispatchMessage(message);
            return;
        }
    }
}
