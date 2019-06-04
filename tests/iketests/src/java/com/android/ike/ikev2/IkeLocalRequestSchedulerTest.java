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

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.android.ike.ikev2.IkeLocalRequestScheduler.IProcedureConsumer;
import com.android.ike.ikev2.IkeLocalRequestScheduler.LocalRequest;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

public final class IkeLocalRequestSchedulerTest {
    private IkeLocalRequestScheduler mScheduler;

    private IProcedureConsumer mMockConsumer;
    private LocalRequest[] mMockRequestArray;

    private ArgumentCaptor<LocalRequest> mLocalRequestCaptor =
            ArgumentCaptor.forClass(LocalRequest.class);

    @Before
    public void setUp() {
        mMockConsumer = mock(IProcedureConsumer.class);
        mScheduler = new IkeLocalRequestScheduler(mMockConsumer);

        mMockRequestArray = new LocalRequest[10];
        for (int i = 0; i < mMockRequestArray.length; i++) {
            mMockRequestArray[i] = mock(LocalRequest.class);
        }
    }

    @Test
    public void testAddMultipleRequestProcessOnlyOne() {
        for (LocalRequest r : mMockRequestArray) mScheduler.addRequest(r);

        // Check that the onNewPrcedureReady called exactly once, on the first item
        verify(mMockConsumer, times(1)).onNewProcedureReady(any());
        verify(mMockConsumer, times(1)).onNewProcedureReady(mMockRequestArray[0]);
        for (int i = 1; i < mMockRequestArray.length; i++) {
            verify(mMockConsumer, never()).onNewProcedureReady(mMockRequestArray[i]);
        }
    }

    @Test
    public void testFinishLocalProcedureWithRequestAwaiting() {
        for (LocalRequest r : mMockRequestArray) mScheduler.addRequest(r);

        for (int i = 0; i < mMockRequestArray.length; i++) {
            // Verify the calling times and the latest processed LocalRequest
            verify(mMockConsumer, times(i + 1)).onNewProcedureReady(mLocalRequestCaptor.capture());
            assertEquals(mMockRequestArray[i], mLocalRequestCaptor.getValue());

            mScheduler.finishLocalProcedure();
        }

        verify(mMockConsumer, times(mMockRequestArray.length)).onNewProcedureReady(any());
    }

    @Test
    public void testFinishLocalProcedureWithNoRequestAwaiting() {
        mScheduler.addRequest(mock(LocalRequest.class));
        verify(mMockConsumer, times(1)).onNewProcedureReady(any());

        mScheduler.finishLocalProcedure();
        verify(mMockConsumer, times(1)).onNewProcedureReady(any());
    }

    @Test
    public void testFinishRemoteProcedureWithRequestAwaiting() {
        mScheduler.startRemoteProcedure();
        mScheduler.addRequest(mock(LocalRequest.class));

        verify(mMockConsumer, never()).onNewProcedureReady(any());

        mScheduler.finishRemoteProcedure();
        verify(mMockConsumer).onNewProcedureReady(any());
    }

    @Test
    public void testFinishRemoteProcedureWithNoRequestAwaiting() {
        mScheduler.startRemoteProcedure();
        mScheduler.finishRemoteProcedure();
        verify(mMockConsumer, never()).onNewProcedureReady(any());
    }

    @Test
    public void testProcessOrder() {
        InOrder inOrder = inOrder(mMockConsumer);

        for (LocalRequest r : mMockRequestArray) mScheduler.addRequest(r);
        for (int i = 0; i < mMockRequestArray.length; i++) mScheduler.finishLocalProcedure();

        for (LocalRequest r : mMockRequestArray) {
            inOrder.verify(mMockConsumer).onNewProcedureReady(r);
        }
    }

    @Test
    public void testAddRequestToFrontProcessOrder() {
        InOrder inOrder = inOrder(mMockConsumer);

        LocalRequest[] mockHighPriorityRequestArray = new LocalRequest[10];
        for (int i = 0; i < mockHighPriorityRequestArray.length; i++) {
            mockHighPriorityRequestArray[i] = mock(LocalRequest.class);
        }

        mScheduler.startRemoteProcedure();
        for (LocalRequest r : mMockRequestArray) mScheduler.addRequest(r);
        for (LocalRequest r : mockHighPriorityRequestArray) mScheduler.addRequestAtFront(r);

        mScheduler.finishRemoteProcedure();
        for (int i = 0; i < mockHighPriorityRequestArray.length + mMockRequestArray.length; i++) {
            mScheduler.finishLocalProcedure();
        }

        // Verify processing order. mockHighPriorityRequestArray is processed in reverse order
        for (int i = mockHighPriorityRequestArray.length - 1; i >= 0; i--) {
            inOrder.verify(mMockConsumer).onNewProcedureReady(mockHighPriorityRequestArray[i]);
        }
        for (LocalRequest r : mMockRequestArray) {
            inOrder.verify(mMockConsumer).onNewProcedureReady(r);
        }
    }
}
