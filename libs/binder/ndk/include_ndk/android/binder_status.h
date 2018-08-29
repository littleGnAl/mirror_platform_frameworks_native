/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

// Keep the exception codes in sync with android/os/Parcel.java.
enum {
    EX_NONE = 0,
    EX_SECURITY = -1,
    EX_BAD_PARCELABLE = -2,
    EX_ILLEGAL_ARGUMENT = -3,
    EX_NULL_POINTER = -4,
    EX_ILLEGAL_STATE = -5,
    EX_NETWORK_MAIN_THREAD = -6,
    EX_UNSUPPORTED_OPERATION = -7,
    EX_SERVICE_SPECIFIC = -8,
    EX_PARCELABLE = -9,

    /**
     * This is special, and indicates to native binder proxies that the
     * transaction has failed at a low level.
     */
    EX_TRANSACTION_FAILED = -129,
};

/**
 * One of the above values, -errno, or positive for custom service return values.
 */
typedef int32_t binder_status_t;

/**
 * This is a helper class that encapsulates a standard way to keep track of and chain binder errors along with service specific errors.
 *
 * It is not required to be used in order to parcel/receive transactions, but it is required in order
 * to be compatible with standard AIDL transactions.
 */
struct AStatus;
typedef struct AStatus AStatus;

/**
 * New object which is considered a success.
 */
AStatus* AStatus_newOk();

/**
 * New object with a service speciic error.
 */
AStatus* AStatus_newServiceSpecific(binder_status_t ex);

/**
 * New object with a service specific error and message.
 */
AStatus* AStatus_newServiceSpecificWithMessage(binder_status_t ex, const char* message);

/**
 * Deletes memory associated with the status object.
 */
void AStatus_delete(AStatus* status);

__END_DECLS
