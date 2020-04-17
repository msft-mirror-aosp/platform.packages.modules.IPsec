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

import android.util.CloseGuard;
import android.util.Pair;

import java.io.IOException;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
 * This class represents a reserved IKE SPI.
 *
 * <p>This class is created to avoid assigning same SPI to the same address.
 *
 * <p>Objects of this type are used to track reserved IKE SPI to avoid SPI collision. They can be
 * obtained by calling {@link #allocateSecurityParameterIndex()} and must be released by calling
 * {@link #close()} when they are no longer needed.
 *
 * <p>This class MUST only be called from IKE worker thread. Methods that allocate and close IKE
 * SPI resource are not thread safe.
 *
 * <p>This class follows the pattern of {@link IpSecManager.SecurityParameterIndex}.
 */
public final class IkeSecurityParameterIndex implements AutoCloseable {
    // Remember assigned IKE SPIs to avoid SPI collision.
    private static final Set<Pair<InetAddress, Long>> sAssignedIkeSpis = new HashSet<>();
    private static final int MAX_ASSIGN_IKE_SPI_ATTEMPTS = 100;
    private static final SecureRandom IKE_SPI_RANDOM = new SecureRandom();

    private final InetAddress mSourceAddress;
    private final long mSpi;
    private final CloseGuard mCloseGuard = new CloseGuard();

    private IkeSecurityParameterIndex(InetAddress sourceAddress, long spi) {
        mSourceAddress = sourceAddress;
        mSpi = spi;
        mCloseGuard.open("close");
    }

    /**
     * Get a new IKE SPI and maintain the reservation.
     *
     * @return an instance of IkeSecurityParameterIndex.
     */
    public static IkeSecurityParameterIndex allocateSecurityParameterIndex(
            InetAddress sourceAddress) throws IOException {
        // TODO: Create specific Exception for SPI assigning error.

        for (int i = 0; i < MAX_ASSIGN_IKE_SPI_ATTEMPTS; i++) {
            long spi = IKE_SPI_RANDOM.nextLong();
            // Zero value can only be used in the IKE responder SPI field of an IKE INIT
            // request.
            if (spi != 0L
                    && sAssignedIkeSpis.add(new Pair<InetAddress, Long>(sourceAddress, spi))) {
                return new IkeSecurityParameterIndex(sourceAddress, spi);
            }
        }

        throw new IOException("Failed to generate IKE SPI.");
    }

    /**
     * Get a new IKE SPI and maintain the reservation.
     *
     * @return an instance of IkeSecurityParameterIndex.
     */
    public static IkeSecurityParameterIndex allocateSecurityParameterIndex(
            InetAddress sourceAddress, long requestedSpi) throws IOException {
        if (sAssignedIkeSpis.add(new Pair<InetAddress, Long>(sourceAddress, requestedSpi))) {
            return new IkeSecurityParameterIndex(sourceAddress, requestedSpi);
        }

        throw new IOException(
                "Failed to generate IKE SPI for "
                        + requestedSpi
                        + " with source address "
                        + sourceAddress.getHostAddress());
    }

    /**
     * Get the underlying SPI held by this object.
     *
     * @return the underlying IKE SPI.
     */
    public long getSpi() {
        return mSpi;
    }

    /** Release an SPI that was previously reserved. */
    @Override
    public void close() {
        sAssignedIkeSpis.remove(new Pair<InetAddress, Long>(mSourceAddress, mSpi));
        mCloseGuard.close();
    }

    /** Check that the IkeSecurityParameterIndex was closed properly. */
    @Override
    protected void finalize() throws Throwable {
        if (mCloseGuard != null) {
            mCloseGuard.warnIfOpen();
        }
        close();
    }
}
