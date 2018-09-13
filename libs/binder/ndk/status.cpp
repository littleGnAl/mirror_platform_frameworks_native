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

#include <android/binder_status.h>
#include "status_internal.h"

using ::android::status_t;
using ::android::binder::Status;

namespace BinderStatus {

binder_status_t FromStatusT(status_t status) {
    if (status > 0) return status;

    switch (status) {
        case ::android::OK:
            return STATUS_OK;

        case ::android::NO_MEMORY:
            return STATUS_NO_MEMORY;
        case ::android::INVALID_OPERATION:
            return STATUS_INVALID_OPERATION;
        case ::android::BAD_VALUE:
            return STATUS_BAD_VALUE;
        case ::android::BAD_TYPE:
            return STATUS_BAD_TYPE;
        case ::android::NAME_NOT_FOUND:
            return STATUS_NAME_NOT_FOUND;
        case ::android::PERMISSION_DENIED:
            return STATUS_PERMISSION_DENIED;
        case ::android::NO_INIT:
            return STATUS_NO_INIT;
        case ::android::ALREADY_EXISTS:
            return STATUS_ALREADY_EXISTS;
        case ::android::DEAD_OBJECT:
            return STATUS_DEAD_OBJECT;
        case ::android::FAILED_TRANSACTION:
            return STATUS_FAILED_TRANSACTION;
        case ::android::BAD_INDEX:
            return STATUS_BAD_INDEX;
        case ::android::NOT_ENOUGH_DATA:
            return STATUS_NOT_ENOUGH_DATA;
        case ::android::WOULD_BLOCK:
            return STATUS_WOULD_BLOCK;
        case ::android::TIMED_OUT:
            return STATUS_TIMED_OUT;
        case ::android::UNKNOWN_TRANSACTION:
            return STATUS_UNKNOWN_TRANSACTION;
        case ::android::FDS_NOT_ALLOWED:
            return STATUS_FDS_NOT_ALLOWED;
        case ::android::UNEXPECTED_NULL:
            return STATUS_UNEXPECTED_NULL;

        case ::android::UNKNOWN_ERROR:
        default:
            return STATUS_UNKNOWN_ERROR;
    }
}

binder_status_t FromException(int32_t exception) {
    switch (exception) {
        case Status::EX_NONE:
            return STATUS_OK;

        case Status::EX_SECURITY:
            return EXCEPTION_SECURITY;
        case Status::EX_BAD_PARCELABLE:
            return EXCEPTION_BAD_PARCELABLE;
        case Status::EX_ILLEGAL_ARGUMENT:
            return EXCEPTION_ILLEGAL_ARGUMENT;
        case Status::EX_NULL_POINTER:
            return EXCEPTION_NULL_POINTER;
        case Status::EX_ILLEGAL_STATE:
            return EXCEPTION_ILLEGAL_STATE;
        case Status::EX_NETWORK_MAIN_THREAD:
            return EXCEPTION_NETWORK_MAIN_THREAD;
        case Status::EX_UNSUPPORTED_OPERATION:
            return EXCEPTION_UNSUPPORTED_OPERATION;
        case Status::EX_PARCELABLE:
            return EXCEPTION_PARCELABLE;

        case Status::EX_TRANSACTION_FAILED:
        default:
            return EXCEPTION_TRANSACTION_FAILED;
    }
}

status_t ToStatusT(binder_status_t binderStatus) {
    if (binderStatus > 0) return binderStatus;

    switch (binderStatus) {
        case STATUS_OK:
            return ::android::OK;

        case STATUS_NO_MEMORY:
            return ::android::NO_MEMORY;
        case STATUS_INVALID_OPERATION:
            return ::android::INVALID_OPERATION;
        case STATUS_BAD_VALUE:
            return ::android::BAD_VALUE;
        case STATUS_BAD_TYPE:
            return ::android::BAD_TYPE;
        case STATUS_NAME_NOT_FOUND:
            return ::android::NAME_NOT_FOUND;
        case STATUS_PERMISSION_DENIED:
            return ::android::PERMISSION_DENIED;
        case STATUS_NO_INIT:
            return ::android::NO_INIT;
        case STATUS_ALREADY_EXISTS:
            return ::android::ALREADY_EXISTS;
        case STATUS_DEAD_OBJECT:
            return ::android::DEAD_OBJECT;
        case STATUS_FAILED_TRANSACTION:
            return ::android::FAILED_TRANSACTION;
        case STATUS_BAD_INDEX:
            return ::android::BAD_INDEX;
        case STATUS_NOT_ENOUGH_DATA:
            return ::android::NOT_ENOUGH_DATA;
        case STATUS_WOULD_BLOCK:
            return ::android::WOULD_BLOCK;
        case STATUS_TIMED_OUT:
            return ::android::TIMED_OUT;
        case STATUS_UNKNOWN_TRANSACTION:
            return ::android::UNKNOWN_TRANSACTION;
        case STATUS_FDS_NOT_ALLOWED:
            return ::android::FDS_NOT_ALLOWED;
        case STATUS_UNEXPECTED_NULL:
            return ::android::UNEXPECTED_NULL;

        case STATUS_UNKNOWN_ERROR:
        default:
            return ::android::UNKNOWN_ERROR;
    }
}

int32_t ToException(binder_status_t binderStatus) {
    switch (binderStatus) {
        case STATUS_OK:
            return Status::EX_NONE;

        case EXCEPTION_SECURITY:
            return Status::EX_SECURITY;
        case EXCEPTION_BAD_PARCELABLE:
            return Status::EX_BAD_PARCELABLE;
        case EXCEPTION_ILLEGAL_ARGUMENT:
            return Status::EX_ILLEGAL_ARGUMENT;
        case EXCEPTION_NULL_POINTER:
            return Status::EX_NULL_POINTER;
        case EXCEPTION_ILLEGAL_STATE:
            return Status::EX_ILLEGAL_STATE;
        case EXCEPTION_NETWORK_MAIN_THREAD:
            return Status::EX_NETWORK_MAIN_THREAD;
        case EXCEPTION_UNSUPPORTED_OPERATION:
            return Status::EX_UNSUPPORTED_OPERATION;
        case EXCEPTION_PARCELABLE:
            return Status::EX_PARCELABLE;

        case EXCEPTION_TRANSACTION_FAILED:
        default:
            return Status::EX_TRANSACTION_FAILED;
    }
}

binder_status_t FromMixed(int32_t mixedValue) {
    // priority for status_t based on the known cases in libhwbinder (see b/115654595).
    binder_status_t status = FromStatusT(mixedValue);
    if (status == STATUS_UNKNOWN_ERROR && mixedValue != ::android::UNKNOWN_ERROR) {
        status = FromException(mixedValue);
    }
    return status;
}

int32_t ToMixed(binder_status_t status) {
    int32_t mixedValue = ToException(status);
    if (mixedValue == Status::EX_TRANSACTION_FAILED && status != EXCEPTION_TRANSACTION_FAILED) {
        mixedValue = ToStatusT(status);
    }
    return mixedValue;
}

Status Unpack(binder_status_t binderStatus) {
    if (binderStatus == STATUS_OK) {
        return Status::ok();
    }

    if (binderStatus > 0) {
        return Status::fromServiceSpecificError(binderStatus);
    }

    if (binderStatus == STATUS_UNKNOWN_ERROR) {
        return Status::fromStatusT(::android::UNKNOWN_ERROR);
    }

    status_t status = ToStatusT(binderStatus);
    if (status != ::android::UNKNOWN_ERROR) {
        return Status::fromStatusT(status);
    }

    int32_t exception = ToException(binderStatus);
    return Status::fromExceptionCode(exception);
}

} // namespace BinderStatus
