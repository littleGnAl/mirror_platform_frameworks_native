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

#pragma once

#include <cstdint>
#include <memory>

#include <utils/Errors.h>
#include <android-base/unique_fd.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Status.h>

// ---------------------------------------------------------------------------
// Implemented in Rust

extern "C" {

// An opaque pointer to any Rust struct. This is initialized when creating a
// BinderNative wrapper and passed back to the TransactCallback for onTransact.
struct RustObject;

}

// ---------------------------------------------------------------------------
// Implemented in C++

namespace android {

namespace c_interface {

// Expose error codes from anonymous enum in utils/Errors.h
enum Error {
    OK = OK,
    NO_ERROR = NO_ERROR,
    UNKNOWN_ERROR = UNKNOWN_ERROR,
    NO_MEMORY = NO_MEMORY,
    INVALID_OPERATION = INVALID_OPERATION,
    BAD_VALUE = BAD_VALUE,
    BAD_TYPE = BAD_TYPE,
    NAME_NOT_FOUND = NAME_NOT_FOUND,
    PERMISSION_DENIED = PERMISSION_DENIED,
    NO_INIT = NO_INIT,
    ALREADY_EXISTS = ALREADY_EXISTS,
    DEAD_OBJECT = DEAD_OBJECT,
    FAILED_TRANSACTION = FAILED_TRANSACTION,
    BAD_INDEX = BAD_INDEX,
    NOT_ENOUGH_DATA = NOT_ENOUGH_DATA,
    WOULD_BLOCK = WOULD_BLOCK,
    TIMED_OUT = TIMED_OUT,
    UNKNOWN_TRANSACTION = UNKNOWN_TRANSACTION,
    FDS_NOT_ALLOWED = FDS_NOT_ALLOWED,
    UNEXPECTED_NULL = UNEXPECTED_NULL,
};

class RustBBinder;
class RustDeathRecipient;

sp<IBinder>* Sp_CloneIBinder(const sp<IBinder> *sp);
sp<RustDeathRecipient>* Sp_CloneRustDeathRecipient(const sp<RustDeathRecipient>* sp);
wp<RustDeathRecipient>* Sp_DowngradeRustDeathRecipient(const sp<RustDeathRecipient>* sp);
wp<RustDeathRecipient>* Wp_CloneRustDeathRecipient(const wp<RustDeathRecipient>* wp);
sp<RustDeathRecipient>* Wp_PromoteRustDeathRecipient(const wp<RustDeathRecipient>* wp);
wp<RustBBinder>* Sp_DowngradeRustBBinder(const sp<RustBBinder> *sp);
wp<RustBBinder>* Wp_CloneRustBBinder(const wp<RustBBinder>* wp);
sp<RustBBinder>* Wp_PromoteRustBBinder(const wp<RustBBinder>* wp);
int32_t Sp_StrongCountIBinder(const sp<IBinder>* sp_ib);
sp<IBinder>* Wp_PromoteIBinder(const wp<IBinder>* wp_ib);
wp<IBinder>* Wp_CloneIBinder(const wp<IBinder> *wp);
void Sp_DropIBinder(sp<IBinder> *sp);
void Wp_DropIBinder(wp<IBinder> *wp);
sp<IServiceManager>* Sp_CloneIServiceManager(const sp<IServiceManager> *sp);
void Sp_DropIServiceManager(sp<IServiceManager> *sp);
void Sp_DropRustBBinder(sp<RustBBinder> *sp);
sp<IInterface>* Sp_CloneIInterface(const sp<IInterface> *sp);
void Sp_DropIInterface(sp<IInterface> *sp);

IBinder* Sp_getIBinder(sp<IBinder> *sp);
IServiceManager* Sp_getIServiceManager(sp<IServiceManager> *sp);
IInterface* Sp_getIInterface(sp<IInterface> *sp);
RustBBinder* Sp_getRustBBinder(sp<RustBBinder> *sp);

typedef status_t(TransactCallback)(RustBBinder *binder, RustObject* object, uint32_t code,
                                   const Parcel* data, Parcel* reply, uint32_t flags);
typedef void(DestructCallback)(RustObject* object);
typedef void(BinderDiedCallback)(const RustObject* object, wp<IBinder>* who);

sp<RustBBinder>* NewRustBBinder(RustObject* object, const String16* descriptor,
                                  TransactCallback* transactCallback,
                                  DestructCallback* destructCallback);
sp<RustDeathRecipient>* NewRustDeathRecipient(RustObject* object, BinderDiedCallback* binderDied,
                                              DestructCallback* destructCallback);
status_t RustBBinder_writeToParcel(const sp<RustBBinder>* binder, Parcel* parcel);
void RustBBinder_setExtension(RustBBinder* binder, const sp<IBinder>* ext);
sp<IBinder>* RustBBinder_getExtension(RustBBinder* binder);
sp<IBinder>* RustBBinder_castToIBinder(sp<RustBBinder>* binder);
const IBinder* RustBBinder_asIBinder(const RustBBinder* binder);
IBinder* RustBBinder_asIBinderMut(RustBBinder* binder);
const String16* RustBBinder_getInterfaceDescriptor(const RustBBinder* binder);
bool RustBBinder_isBinderAlive(const RustBBinder* binder);
status_t RustBBinder_pingBinder(RustBBinder* binder);
status_t RustBBinder_dump(RustBBinder* binder, int fd, const String16* const* args, size_t args_len);
status_t RustBBinder_getDebugPid(RustBBinder* binder, pid_t* outPid);
bool RustBBinder_checkSubclass(const RustBBinder* binder, const void* subclassID);
status_t RustBBinder_transact(RustBBinder* binder, uint32_t code, const Parcel* data, Parcel* reply,
                              uint32_t flags);
void Sp_DropRustDeathRecipient(sp<RustDeathRecipient>* sp);
void Wp_DropRustDeathRecipient(wp<RustDeathRecipient>* wp);
void Wp_DropRustBBinder(wp<RustBBinder>* wp);
sp<IServiceManager>* DefaultServiceManager();

// ProcessState methods
void StartThreadPool();
void GiveThreadPoolName();
void FlushCommands();

status_t IBinder_transact(IBinder* binder, uint32_t code, const Parcel* data,
                          Parcel* reply, uint32_t flags);
status_t IBinder_linkToDeath(IBinder* binder, const sp<RustDeathRecipient>* recipient,
                             void* cookie, uint32_t flags);
status_t IBinder_unlinkToDeath(IBinder* binder, const wp<RustDeathRecipient>* recipient,
                               void* cookie, uint32_t flags, wp<IBinder::DeathRecipient>* outPtr);
sp<IInterface>* IBinder_queryLocalInterface(IBinder* binder, const String16* descriptor);
const String16* IBinder_getInterfaceDescriptor(const IBinder* binder);
bool IBinder_isBinderAlive(const IBinder* binder);
status_t IBinder_pingBinder(IBinder* binder);
status_t IBinder_dump(IBinder* binder, int fd, const String16* const* args, size_t args_len);
status_t IBinder_getExtension(IBinder* binder, sp<IBinder>** out);
status_t IBinder_getDebugPid(IBinder* binder, pid_t* outPid);
bool IBinder_checkSubclass(const IBinder* binder, const void* subclassID);

Parcel* NewParcel();
status_t Parcel_readStrongBinder(const Parcel* parcel, sp<IBinder>** binder);
status_t Parcel_readString8(const Parcel* parcel, String8** string);
status_t Parcel_readString16(const Parcel* parcel, String16** string);
status_t Parcel_readBlob(const Parcel* parcel, size_t len, Parcel::ReadableBlob** blob);
status_t Parcel_writeBlob(Parcel* parcel, size_t len, bool mutableCopy,
                          Parcel::WritableBlob** blob);
const void* Parcel_ReadableBlob_data(const Parcel::ReadableBlob* blob);
void* Parcel_WritableBlob_data(Parcel::WritableBlob* blob);
size_t Parcel_ReadableBlob_size(const Parcel::ReadableBlob* blob);
size_t Parcel_WritableBlob_size(const Parcel::WritableBlob* blob);
void Parcel_ReadableBlob_clear(Parcel::ReadableBlob* blob);
void Parcel_WritableBlob_clear(Parcel::WritableBlob* blob);
void Parcel_ReadableBlob_release(Parcel::ReadableBlob* blob);
void Parcel_WritableBlob_release(Parcel::WritableBlob* blob);
void Parcel_ReadableBlob_Destructor(Parcel::ReadableBlob* blob);
void Parcel_WritableBlob_Destructor(Parcel::WritableBlob* blob);

typedef void(ListServiceCallback)(const String16* service, void* context);
void IServiceManager_listServices(IServiceManager* self, int dumpsysFlags,
                                  ListServiceCallback* callback, void* context);
const String16* IServiceManager_getInterfaceDescriptor(const IServiceManager* self);
sp<IBinder>* IServiceManager_getService(const IServiceManager* self, const String16* name);
sp<IBinder>* IServiceManager_checkService(const IServiceManager* self, const String16* name);
status_t IServiceManager_addService(IServiceManager* self, const String16* name,
                                    const sp<IBinder>* service, bool allowIsolated,
                                    int dumpsysFlags);
sp<IBinder>* IServiceManager_waitForService(IServiceManager* self, const String16* name);
bool IServiceManager_isDeclared(IServiceManager* self, const String16* name);

String8* NewString8();
String8* NewString8FromUtf16(const char16_t* data, size_t len);
String8* NewString8FromUtf8(const char* data, size_t len);
const char* String8_data(const String8* S);
void String8_Destroy(String8* S);

String16* NewString16();
String16* CopyString16(const String16* S);
String16* NewString16FromUtf16(const char16_t* data, size_t len);
String16* NewString16FromUtf8(const char* data, size_t len);
const char16_t* String16_data(const String16* S);
void String16_Destroy(String16* S);

base::unique_fd* NewUniqueFd();
void UniqueFd_reset(base::unique_fd* self, int newValue);
void UniqueFd_destructor(base::unique_fd* self);

} // namespace c_interface

} // namespace android
