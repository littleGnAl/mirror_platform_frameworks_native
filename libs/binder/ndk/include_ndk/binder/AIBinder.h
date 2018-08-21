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

#include <binder/AParcel.h>
#include <binder/AStatus.h>

__BEGIN_DECLS

// See TF_* in kernel's binder.h
typedef uint32_t binder_flags_t;
typedef uint32_t transaction_code_t;

// FIXME: de-dupe transaction codes, rename?

/**
 * The first transaction code available for user commands.
 */
const uint32_t FIRST_CALL_TRANSACTION = 0x00000001;
/**
 * The last transaction code available for user commands.
 */
const uint32_t LAST_CALL_TRANSACTION = 0x00ffffff;

struct AIBinder;
typedef struct AIBinder AIBinder;

struct AIBinder_Class;
typedef struct AIBinder_Class AIBinder_Class;

typedef void* AIBinder_Class_Impl;

typedef AIBinder_Class_Impl (*AIBinder_Class_onCreate)(void* args);
typedef void (*AIBinder_Class_onDestroy)(AIBinder_Class_Impl impl);
typedef service_status_t (*AIBinder_Class_onTransact)(transaction_code_t code, AIBinder* binder,
                                                      AParcel* in, AParcel* out);

AIBinder_Class* AIBinder_Class_define(const char* interfaceDescriptor,
                                      AIBinder_Class_onCreate onCreate,
                                      AIBinder_Class_onDestroy onDestroy,
                                      AIBinder_Class_onTransact onTransact);

/**
 * Creates a new binder object of the appropriate class.
 *
 * FIXME: should automatically incStrong?
 */
AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args);
AStatus* AIBinder_transact(transaction_code_t code, AIBinder* binder, binder_flags_t flags,
                           AParcel* in, AParcel* out);
// FIXME: should this be visible in the NDK API?
// FIXME: this should take an ABinderProcess object or we should remove that object
AStatus* AIBinder_register(AIBinder* binder, const char* instance);
AIBinder_Class_Impl AIBinder_getImpl(AIBinder* binder);

// FIXME: refcounting
// void AIBinder_incStrong(AIBinder* binder);
// void AIBinder_decStrong(AIBinder* binder);

__END_DECLS
