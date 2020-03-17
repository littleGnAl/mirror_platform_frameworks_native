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

#include "BinderInterface.h"

#include <binder/Binder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <utils/StrongPointer.h>

namespace android {

namespace c_interface {

class BinderNative : public BBinder {
 public:
  BinderNative(RustObject* object, const String16* descriptor, TransactCallback* callback)
    : mObject(object), mTransactCallback(callback), mDescriptor(*descriptor) {}

  virtual const String16& getInterfaceDescriptor() const override {
    return mDescriptor;
  }

 protected:
  status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                      uint32_t flags = 0) override {
    return mTransactCallback(mObject, code, &data, reply, flags);
  }

 private:
  // Rust remotable object
  RustObject* mObject;
  TransactCallback* mTransactCallback;
  String16 mDescriptor;
};

sp<BinderNative>* NewBinderNative(RustObject* object, const String16* descriptor,
                                  TransactCallback* callback) {
  return new sp(new BinderNative(object, descriptor, callback));
}

status_t BinderNative_writeToParcel(sp<BinderNative>* binder, Parcel* parcel) {
  assert(binder && parcel);
  return parcel->writeStrongBinder(*binder);
}

sp<IServiceManager>* DefaultServiceManager() {
  return new sp(defaultServiceManager());
}

IPCThreadState* GetThreadState() {
  return IPCThreadState::self();
}
void StartThreadPool() {
  ProcessState::self()->startThreadPool();
}
void FlushCommands() {
  IPCThreadState::self()->flushCommands();
}

status_t IBinder_transact(IBinder* binder, uint32_t code, const Parcel* data,
                          Parcel* reply, uint32_t flags) {
  assert(binder && data && reply);
  return binder->transact(code, *data, reply, flags);
}
sp<IInterface>* IBinder_queryLocalInterface(IBinder* binder, const String16* descriptor) {
  assert(binder && descriptor);
  return new sp(binder->queryLocalInterface(*descriptor));
}
const String16* IBinder_getInterfaceDescriptor(IBinder* binder) {
  assert(binder);
  return &binder->getInterfaceDescriptor();
}

Parcel* NewParcel() {
  return new Parcel;
}
status_t Parcel_readStrongBinder(const Parcel* parcel, sp<IBinder>** binder) {
  assert(parcel && binder);
  *binder = new sp<IBinder>;
  return parcel->readStrongBinder(*binder);
}
status_t Parcel_readString16(const Parcel* parcel, String16** string) {
  assert(parcel && string);
  *string = new String16;
  return parcel->readString16(*string);
}

const String16* IServiceManager_getInterfaceDescriptor(const IServiceManager* self) {
  assert(self);
  return &self->getInterfaceDescriptor();
}
sp<IBinder>* IServiceManager_getService(const IServiceManager* self, const String16* name) {
  assert(self && name);
  return new sp(self->getService(*name));
}

String16* NewString16() {
  return new String16;
}
String16* NewString16FromUtf16(const char16_t* data, size_t len) {
  return new String16(data, len);
}
String16* NewString16FromUtf8(const char* data, size_t len) {
  return new String16(data, len);
}

} // namespace c_interface

} // namespace android
