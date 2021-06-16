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

package com.android.internal.net.ipsec.ike.utils;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.os.SystemClock;

/** IkeAlarm provides interfaces to use AlarmManager for scheduling system alarm. */
public abstract class IkeAlarm {
    protected final AlarmManager mAlarmManager;
    protected final String mTag;
    protected final long mDelayMs;

    private IkeAlarm(IkeAlarmConfig alarmConfig) {
        mAlarmManager = alarmConfig.context.getSystemService(AlarmManager.class);
        mTag = alarmConfig.tag;
        mDelayMs = alarmConfig.delayMs;
    }

    /** Creates an alarm to be delivered precisely at the stated time. */
    public static IkeAlarm newExactAlarm(IkeAlarmConfig alarmConfig) {
        return new IkeAlarmWithPendingIntent(alarmConfig, false /* allowWhileIdle */);
    }

    /**
     * Creates an alarm to be delivered precisely at the stated time, even when the system is in
     * low-power idle (a.k.a. doze) modes.
     */
    public static IkeAlarm newExactAndAllowWhileIdleAlarm(IkeAlarmConfig alarmConfig) {
        // TODO: Do not use PendingIntent if it is system uid. Done in the followup CL.
        return new IkeAlarmWithPendingIntent(alarmConfig, true /* allowWhileIdle */);
    }

    /** Cancel the alarm */
    public abstract void cancel();

    /** Schedule/re-schedule the alarm */
    public abstract void schedule();

    /** Alarm that will be using a PendingIntent */
    private static class IkeAlarmWithPendingIntent extends IkeAlarm {
        private final PendingIntent mPendingIntent;
        private final boolean mAllowWhileIdle;

        IkeAlarmWithPendingIntent(IkeAlarmConfig alarmConfig, boolean allowWhileIdle) {
            super(alarmConfig);
            android.util.Log.d("IKE", "new IkeAlarmWithPendingIntent for " + mTag);

            mPendingIntent = alarmConfig.pendingIntent;
            mAllowWhileIdle = allowWhileIdle;
        }

        @Override
        public void cancel() {
            mAlarmManager.cancel(mPendingIntent);
            mPendingIntent.cancel();
        }

        @Override
        public void schedule() {
            if (mAllowWhileIdle) {
                mAlarmManager.setExactAndAllowWhileIdle(
                        AlarmManager.ELAPSED_REALTIME_WAKEUP,
                        SystemClock.elapsedRealtime() + mDelayMs,
                        mPendingIntent);
            } else {
                mAlarmManager.setExact(
                        AlarmManager.ELAPSED_REALTIME_WAKEUP,
                        SystemClock.elapsedRealtime() + mDelayMs,
                        mPendingIntent);
            }
        }
    }

    // TODO: Create IkeAlarm that will use direct callback instead of PendingIntent. Done in the
    // followup CL.

    /** Configurations of creating an IkeAlarm */
    public static class IkeAlarmConfig {
        public final Context context;
        public final String tag;
        public final long delayMs;
        public final PendingIntent pendingIntent;

        public IkeAlarmConfig(
                Context context, String tag, long delayMs, PendingIntent pendingIntent) {
            this.context = context;
            this.tag = tag;
            this.delayMs = delayMs;
            this.pendingIntent = pendingIntent;
        }
    }
}
