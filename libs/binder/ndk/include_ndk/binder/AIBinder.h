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

/**
 * The first transaction code available for user commands.
 */
const transaction_code_t FIRST_CALL_TRANSACTION = 0x00000001;
/**
 * The last transaction code available for user commands.
 */
const transaction_code_t LAST_CALL_TRANSACTION = 0x00ffffff;

/**
 * Represents a local or remote object which can be used for IPC or which can itself be sent.
 */
struct AIBinder;
typedef struct AIBinder AIBinder;

/**
 * Represents a type of AIBinder object which can be sent out.
 */
struct AIBinder_Class;
typedef struct AIBinder_Class AIBinder_Class;

/**
 * Represents an arbitrary piece of data that is to act as the instance data for an AIBinder_Class.
 * Most commonly, this is the class itself that implements the desired functionality and
 * marshalling/unmarshalling code is kept separately.
 */
typedef void* AIBinder_Class_Impl;

/**
 * This is called whenever a new AIBinder object is needed of a specific class.
 */
typedef AIBinder_Class_Impl (*AIBinder_Class_onCreate)(void* args);
/**
 * This is called whenever an AIBinder object is no longer referenced and needs destroyed.
 *
 * Typically, this just deletes whatever the implementation is.
 */
typedef void (*AIBinder_Class_onDestroy)(AIBinder_Class_Impl impl);
/**
 * This is called whenever a transaction needs to be processed by a local implementation.
 */
typedef binder_status_t (*AIBinder_Class_onTransact)(transaction_code_t code, AIBinder* binder,
                                                     const AParcel* in, AParcel* out);

/**
 * An interfaceDescriptor uniquely identifies the type of object that is being created. This is used
 * internally for sanity checks on transactions.
 *
 * None of these parameters can be nullptr.
 */
AIBinder_Class* AIBinder_Class_define(const char* interfaceDescriptor,
                                      AIBinder_Class_onCreate onCreate,
                                      AIBinder_Class_onDestroy onDestroy,
                                      AIBinder_Class_onTransact onTransact);

/**
 * Creates a new binder object of the appropriate class.
 *
 * FIXME: implement this
 * Ownership of args is passed to this object. The lifecycle is implemented with AIBinder_incStrong
 * and AIBinder_decStrong. When the reference count reaches zero, onDestroy is called.
 */
AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args);

// FIXME: replace with usage of incStrong/decStrong
void AIBinder_delete(AIBinder* binder);

/**
 * This sets the class of a remote AIBinder object. This checks to make sure the remote object is of
 * the expected class. A class must be set in order to use transactions on an AIBinder object.
 * However, if an object is just intended to be passed through to another process, this need not be
 * called.
 */
bool AIBinder_setClass(AIBinder* binder, const AIBinder_Class* clazz);

const AIBinder_Class* AIBinder_getClass(AIBinder* binder);
AIBinder_Class_Impl AIBinder_getImpl(AIBinder* binder);

binder_status_t AIBinder_prepareTransaction(const AIBinder* binder, AParcel** in);
binder_status_t AIBinder_transact(transaction_code_t code, const AIBinder* binder, AParcel* in,
                                  binder_flags_t flags, AParcel** out);
binder_status_t AIBinder_finalizeTransaction(const AIBinder* binder, AParcel* out);

// FIXME: move this to an IServiceManager API ??
binder_status_t AIBinder_register(AIBinder* binder, const char* instance);

/**
 * Gets a binder object with this specific instance name. Blocks for a couple of seconds waiting on
 * it.
 */
AIBinder* AIBinder_get(const char* instance);

__END_DECLS
