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

/**
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_status.h
 */

#pragma once

#include <errno.h>
#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

enum {
    STATUS_OK = 0,

    STATUS_UNKNOWN_ERROR = (-2147483647 - 1), // INT32_MIN value
    STATUS_NO_MEMORY = -ENOMEM,
    STATUS_INVALID_OPERATION = -ENOSYS,
    STATUS_BAD_VALUE = -EINVAL,
    STATUS_BAD_TYPE = (STATUS_UNKNOWN_ERROR + 1),
    STATUS_NAME_NOT_FOUND = -ENOENT,
    STATUS_PERMISSION_DENIED = -EPERM,
    STATUS_NO_INIT = -ENODEV,
    STATUS_ALREADY_EXISTS = -EEXIST,
    STATUS_DEAD_OBJECT = -EPIPE,
    STATUS_FAILED_TRANSACTION = (STATUS_UNKNOWN_ERROR + 2),
    STATUS_BAD_INDEX = -EOVERFLOW,
    STATUS_NOT_ENOUGH_DATA = -ENODATA,
    STATUS_WOULD_BLOCK = -EWOULDBLOCK,
    STATUS_TIMED_OUT = -ETIMEDOUT,
    STATUS_UNKNOWN_TRANSACTION = -EBADMSG,
    STATUS_FDS_NOT_ALLOWED = (STATUS_UNKNOWN_ERROR + 7),
    STATUS_UNEXPECTED_NULL = (STATUS_UNKNOWN_ERROR + 8),

    EXCEPTION_SECURITY = STATUS_UNKNOWN_ERROR + 1000 - 1,
    EXCEPTION_BAD_PARCELABLE = STATUS_UNKNOWN_ERROR + 1000 - 2,
    EXCEPTION_ILLEGAL_ARGUMENT = STATUS_UNKNOWN_ERROR + 1000 - 3,
    EXCEPTION_NULL_POINTER = STATUS_UNKNOWN_ERROR + 1000 - 4,
    EXCEPTION_ILLEGAL_STATE = STATUS_UNKNOWN_ERROR + 1000 - 5,
    EXCEPTION_NETWORK_MAIN_THREAD = STATUS_UNKNOWN_ERROR + 1000 - 6,
    EXCEPTION_UNSUPPORTED_OPERATION = STATUS_UNKNOWN_ERROR + 1000 - 7,

    // Service specific exceptions are positive values.

    EXCEPTION_PARCELABLE = STATUS_UNKNOWN_ERROR + 1000 - 9,

    /**
     * This is special, and indicates to native binder proxies that the
     * transaction has failed at a low level.
     */
    EXCEPTION_TRANSACTION_FAILED = STATUS_UNKNOWN_ERROR + 1000 - 129,
};

/**
 * One of the above values.
 *
 * By convention, positive values are considered to mean service-specific exceptions.
 *
 * All unrecognized negative values are coerced into STATUS_UNKNOWN.
 */
typedef int32_t binder_status_t;

__END_DECLS

/** @} */
