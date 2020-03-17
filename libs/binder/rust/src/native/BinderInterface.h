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

#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Status.h>
#include <utils/Errors.h>

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

class BinderNative;

typedef status_t (TransactCallback)(RustObject *object, uint32_t code, const Parcel* data,
                                     Parcel* reply, uint32_t flags);

sp<BinderNative>* NewBinderNative(RustObject* object, const String16* descriptor,
                                  TransactCallback* transactCallback);
status_t BinderNative_writeToParcel(sp<BinderNative>* binder, Parcel* parcel);

sp<IServiceManager>* DefaultServiceManager();

IPCThreadState* GetThreadState();
void StartThreadPool();
void FlushCommands();

status_t IBinder_transact(IBinder* binder, uint32_t code, const Parcel* data,
                          Parcel* reply, uint32_t flags);
sp<IInterface>* IBinder_queryLocalInterface(IBinder* binder, const String16* descriptor);
const String16* IBinder_getInterfaceDescriptor(IBinder* binder);

Parcel* NewParcel();
status_t Parcel_readStrongBinder(const Parcel* parcel, sp<IBinder>** binder);
status_t Parcel_readString16(const Parcel* parcel, String16** string);

const String16* IServiceManager_getInterfaceDescriptor(const IServiceManager* self);
sp<IBinder>* IServiceManager_getService(const IServiceManager* self, const String16* name);

String16* NewString16();
String16* NewString16FromUtf16(const char16_t* data, size_t len);
String16* NewString16FromUtf8(const char* data, size_t len);

} // namespace c_interface

} // namespace android
