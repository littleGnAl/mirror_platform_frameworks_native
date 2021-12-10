/*
 * Copyright (C) 2022 The Android Open Source Project
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

// #define BINDER_DISABLE_LOGGING 1

#ifndef TLOG_TAG
#ifdef LOG_TAG
#define TLOG_TAG "libbinder-" LOG_TAG
#else // LOG_TAG
#define TLOG_TAG "libbinder"
#endif // LOG_TAG
#endif // TLOG_TAG

#include <stdlib.h>
#include <trusty_log.h>

#if BINDER_DISABLE_LOGGING
static inline void __ignore_va_args__(...) {}

#define ALOGD(fmt, ...)                  \
    while (0) {                          \
        __ignore_va_args__(__VA_ARGS__); \
    }
#define ALOGI(fmt, ...)                  \
    while (0) {                          \
        __ignore_va_args__(__VA_ARGS__); \
    }
#define ALOGW(fmt, ...)                  \
    while (0) {                          \
        __ignore_va_args__(__VA_ARGS__); \
    }
#define ALOGE(fmt, ...)                  \
    while (0) {                          \
        __ignore_va_args__(__VA_ARGS__); \
    }
#define ALOGV(fmt, ...)                  \
    while (0) {                          \
        __ignore_va_args__(__VA_ARGS__); \
    }

#define IF_ALOGV() if (false)
#else
#define ALOGD(fmt, ...) TLOGD(fmt "\n", ##__VA_ARGS__)
#define ALOGI(fmt, ...) TLOGI(fmt "\n", ##__VA_ARGS__)
#define ALOGW(fmt, ...) TLOGW(fmt "\n", ##__VA_ARGS__)
#define ALOGE(fmt, ...) TLOGE(fmt "\n", ##__VA_ARGS__)
#define ALOGV(fmt, ...) TLOGI(fmt "\n", ##__VA_ARGS__)

#define IF_ALOGV() if (TLOG_LVL >= TLOG_LVL_INFO)
#endif

#define ALOGI_IF(cond, ...)                \
    do {                                   \
        if (cond) {                        \
            ALOGI(#cond ": " __VA_ARGS__); \
        }                                  \
    } while (0)
#define ALOGE_IF(cond, ...)                \
    do {                                   \
        if (cond) {                        \
            ALOGE(#cond ": " __VA_ARGS__); \
        }                                  \
    } while (0)
#define ALOGW_IF(cond, ...)                \
    do {                                   \
        if (cond) {                        \
            ALOGW(#cond ": " __VA_ARGS__); \
        }                                  \
    } while (0)

#define LOG_ALWAYS_FATAL(fmt, ...)                                \
    do {                                                          \
        TLOGE("libbinder fatal error: " fmt "\n", ##__VA_ARGS__); \
        abort();                                                  \
    } while (0)
#define LOG_ALWAYS_FATAL_IF(cond, ...)                \
    do {                                              \
        if (cond) {                                   \
            LOG_ALWAYS_FATAL(#cond ": " __VA_ARGS__); \
        }                                             \
    } while (0)
#define LOG_FATAL(fmt, ...)                                       \
    do {                                                          \
        TLOGE("libbinder fatal error: " fmt "\n", ##__VA_ARGS__); \
        abort();                                                  \
    } while (0)
#define LOG_FATAL_IF(cond, ...)                \
    do {                                       \
        if (cond) {                            \
            LOG_FATAL(#cond ": " __VA_ARGS__); \
        }                                      \
    } while (0)

#define ALOG_ASSERT(cond, ...) LOG_FATAL_IF(!(cond), ##__VA_ARGS__)

#define android_errorWriteLog(tag, subTag)
