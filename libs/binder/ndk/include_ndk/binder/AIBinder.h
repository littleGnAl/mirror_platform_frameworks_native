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

/*
 * The first transaction code available for user commands (inclusive).
 */
const transaction_code_t FIRST_CALL_TRANSACTION = 0x00000001;
/*
 * The last transaction code available for user commands (inclusive).
 */
const transaction_code_t LAST_CALL_TRANSACTION = 0x00ffffff;

/*
 * Represents a local or remote object which can be used for IPC or which can itself be sent.
 */
struct AIBinder;
typedef struct AIBinder AIBinder;

/*
 * Represents a type of AIBinder object which can be sent out.
 */
struct AIBinder_Class;
typedef struct AIBinder_Class AIBinder_Class;

/*
 * This is called whenever a new AIBinder object is needed of a specific class.
 *
 * These arguments are passed from AIBinder_new. The return value is stored and can be retrieved
 * using AIBinder_getUserData.
 */
typedef void* (*AIBinder_Class_onCreate)(void* args);
/*
 * This is called whenever an AIBinder object is no longer referenced and needs destroyed.
 *
 * Typically, this just deletes whatever the implementation is.
 */
typedef void (*AIBinder_Class_onDestroy)(void* userData);
/*
 * This is called whenever a transaction needs to be processed by a local implementation.
 */
typedef binder_status_t (*AIBinder_Class_onTransact)(transaction_code_t code, AIBinder* binder,
                                                     const AParcel* in, AParcel* out);

/*
 * An interfaceDescriptor uniquely identifies the type of object that is being created. This is used
 * internally for sanity checks on transactions.
 *
 * None of these parameters can be nullptr.
 */
__attribute__((warn_unused_result)) AIBinder_Class* AIBinder_Class_define(
        const char* interfaceDescriptor, AIBinder_Class_onCreate onCreate,
        AIBinder_Class_onDestroy onDestroy, AIBinder_Class_onTransact onTransact);

/*
 * Creates a new binder object of the appropriate class.
 *
 * Ownership of args is passed to this object. The lifecycle is implemented with AIBinder_incStrong
 * and AIBinder_decStrong. When the reference count reaches zero, onDestroy is called.
 *
 * When this is called, the refcount is implicitly 1. So, calling decStrong exactly one time is
 * required to delete this object.
 */
__attribute__((warn_unused_result)) AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args);

/*
 * If this is hosted in a process other than the current one.
 */
// FIXME can't be const since localBinder/remoteBinder aren't const.
bool AIBinder_isRemote(AIBinder* binder);

/*
 * This can only be called if a strong reference to this object already exists in process.
 */
void AIBinder_incStrong(AIBinder* binder);
/*
 * This will delete the object and call onDestroy once the refcount reaches zero.
 */
void AIBinder_decStrong(AIBinder* binder);
/*
 * For debugging only!
 */
int32_t AIBinder_debugGetRefCount(AIBinder* binder);

/*
 * This sets the class of an AIBinder object. This checks to make sure the remote object is of
 * the expected class. A class must be set in order to use transactions on an AIBinder object.
 * However, if an object is just intended to be passed through to another process or used as a
 * handle this need not be called.
 *
 * This transfers (one ref-count of) ownership of the binder object to this function, and the
 * function returns an object which will have one ref-count of ownership to the caller. It is
 * expected to be used like this (doing this retains the same ownership of the binder object that
 * was present in the original binder object): binder = AIBinder_associateClass(binder, ...);
 *
 * The output of this function isn't guaranteed to be equal to the input. Null is returned if the
 * class does not match.
 */
__attribute__((warn_unused_result)) AIBinder* AIBinder_associateClass(AIBinder* binder,
                                                                      const AIBinder_Class* clazz);

const AIBinder_Class* AIBinder_getClass(AIBinder* binder);
void* AIBinder_getUserData(AIBinder* binder);

/*
 * A transaction is a series of calls to these functions which looks this
 * - call AIBinder_prepareTransaction
 * - fill out parcel with in parameters (lifetime of the 'in' variable)
 * - call AIBinder_transact
 * - fill out parcel with out parameters (lifetime of the 'out' variable)
 * - call AIBinder_finalizeTransaction
 */

/*
 * Creates a parcel to start filling out for a transaction. This may add data to the parcel for
 * security, debugging, or other purposes.
 */
binder_status_t AIBinder_prepareTransaction(AIBinder* binder, AParcel** in);
/*
 * Transact using a parcel created from AIBinder_prepareTransaction. This also passes out a parcel
 * to be used for the return transaction.
 */
binder_status_t AIBinder_transact(transaction_code_t code, AIBinder* binder, AParcel* in,
                                  binder_flags_t flags, AParcel** out);
/*
 * This caps off the transaction and may add additional data for security, debugging, or other
 * purposes.
 */
binder_status_t AIBinder_finalizeTransaction(AIBinder* binder, AParcel* out);

/*
 * This registers the service with the default service manager under this instance name.
 */
binder_status_t AIBinder_registerAsService(AIBinder* binder, const char* instance);

/*
 * Gets a binder object with this specific instance name. Blocks for a couple of seconds waiting on
 * it. This also implicitly calls AIBinder_incStrong (so the caller of this function is responsible
 * for calling AIBinder_decStrong).
 */
__attribute__((warn_unused_result)) AIBinder* AIBinder_getService(const char* instance);

__END_DECLS
