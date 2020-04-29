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

#include "BinderBindings.h"

#include <binder/Binder.h>
#include <binder/IResultReceiver.h>
#include <binder/IShellCallback.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>

namespace android {

namespace c_interface {

sp<IBinder>* Sp_CloneIBinder(const sp<IBinder> *ibinder) {
  assert(ibinder);
  return new sp(*ibinder);
}
sp<RustDeathRecipient>* Sp_CloneRustDeathRecipient(const sp<RustDeathRecipient> *rdr) {
  return new sp(*rdr);
}
wp<RustDeathRecipient>* Sp_DowngradeRustDeathRecipient(const sp<RustDeathRecipient> *sp) {
  return new wp(*sp);
}
wp<RustDeathRecipient>* Wp_CloneRustDeathRecipient(const wp<RustDeathRecipient>* wp_rdr) {
  return new wp(*wp_rdr);
}
sp<RustDeathRecipient>* Wp_PromoteRustDeathRecipient(const wp<RustDeathRecipient>* wp_rdr) {
  return new sp(wp_rdr->promote());
}
wp<RustBBinder>* Sp_DowngradeRustBBinder(const sp<RustBBinder> *sp) {
  return new wp(*sp);
}
wp<RustBBinder>* Wp_CloneRustBBinder(const wp<RustBBinder>* wp_rdr) {
  return new wp(*wp_rdr);
}
sp<RustBBinder>* Wp_PromoteRustBBinder(const wp<RustBBinder>* wp_rdr) {
  return new sp(wp_rdr->promote());
}
int32_t Sp_StrongCountIBinder(const sp<IBinder>* sp_ib) {
  return (*sp_ib)->getStrongCount();
}
sp<IBinder>* Wp_PromoteIBinder(const wp<IBinder>* wp_ib) {
  return new sp(wp_ib->promote());
}
wp<IBinder>* Wp_CloneIBinder(const wp<IBinder> *ibinder) {
  return new wp(*ibinder);
}
void Sp_DropIBinder(sp<IBinder> *sp) {
  delete sp;
}
void Wp_DropIBinder(wp<IBinder> *wp) {
  delete wp;
}
sp<IServiceManager>* Sp_CloneIServceManager(const sp<IServiceManager> *ism) {
  assert(ism);
  return new sp(*ism);
}
void Sp_DropIServiceManager(sp<IServiceManager> *sp) {
  delete sp;
}
void Sp_DropRustBBinder(sp<RustBBinder> *sp) {
  delete sp;
}
sp<IInterface>* Sp_CloneIInterface(const sp<IInterface> *iinterface) {
  assert(iinterface);
  return new sp(*iinterface);
}
void Sp_DropIInterface(sp<IInterface> *sp) {
  delete sp;
}

IBinder* Sp_getIBinder(sp<IBinder> *sp) {
  assert(sp);
  return sp->get();
}

IServiceManager* Sp_getIServiceManager(sp<IServiceManager> *sp) {
  assert(sp);
  return sp->get();
}

IInterface* Sp_getIInterface(sp<IInterface> *sp) {
  assert(sp);
  return sp->get();
}

RustBBinder* Sp_getRustBBinder(sp<RustBBinder> *sp) {
  assert(sp);
  return sp->get();
}

class RustBBinder : public BBinder {
 public:
  RustBBinder(RustObject* object, const String16* descriptor, TransactCallback* callback,
               DestructCallback* destruct)
    : mObject(object), mTransactCallback(callback), mDestructCallback(destruct),
      mDescriptor(*descriptor) {}

  virtual const String16& getInterfaceDescriptor() const override {
    return mDescriptor;
  }

 protected:
  status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                      uint32_t flags = 0) override {
    return mTransactCallback(this, mObject, code, &data, reply, flags);
  }

  virtual ~RustBBinder() {
    mDestructCallback(mObject);
  }

 private:
  // Rust remotable object
  RustObject* mObject;
  TransactCallback* mTransactCallback;
  DestructCallback* mDestructCallback;
  String16 mDescriptor;
};

sp<RustBBinder>* NewRustBBinder(RustObject* object, const String16* descriptor,
                                  TransactCallback* callback, DestructCallback* destruct) {
  return new sp(new RustBBinder(object, descriptor, callback, destruct));
}

status_t RustBBinder_writeToParcel(const sp<RustBBinder>* binder, Parcel* parcel) {
  assert(binder && parcel);
  return parcel->writeStrongBinder(*binder);
}

void RustBBinder_setExtension(RustBBinder* binder, const sp<IBinder>* ext) {
  assert(binder && ext);
  return binder->setExtension(*ext);
}

sp<IBinder>* RustBBinder_getExtension(RustBBinder* binder) {
  assert(binder);
  return new sp(binder->getExtension());
}

sp<IBinder>* RustBBinder_castToIBinder(sp<RustBBinder>* binder) {
  assert(binder);
  return new sp<IBinder>(*binder);
}

const IBinder* RustBBinder_asIBinder(const RustBBinder* binder) {
  return binder;
}

IBinder* RustBBinder_asIBinderMut(RustBBinder* binder) {
  return binder;
}

const String16* RustBBinder_getInterfaceDescriptor(const RustBBinder* binder) {
  assert(binder);
  return &binder->getInterfaceDescriptor();
}
bool RustBBinder_isBinderAlive(const RustBBinder* binder) {
  assert(binder);
  return binder->isBinderAlive();
}
status_t RustBBinder_pingBinder(RustBBinder* binder) {
  assert(binder);
  return binder->pingBinder();
}
status_t RustBBinder_dump(RustBBinder* binder, int fd, const String16* const* args, size_t args_len) {
  assert(binder);
  Vector<String16> argsVector;
  if (args) {
    for (size_t i = 0; i < args_len; ++i) {
      assert(*args);
      argsVector.push_back(*args[i]);
    }
  }
  return binder->dump(fd, argsVector);
}
pid_t RustBBinder_getDebugPid(RustBBinder* binder) {
  assert(binder);
  return binder->getDebugPid();
}
bool RustBBinder_checkSubclass(const RustBBinder* binder, const void* subclassID) {
  assert(binder);
  return binder->checkSubclass(subclassID);
}
status_t RustBBinder_transact(RustBBinder* binder, uint32_t code, const Parcel* data,
                              Parcel* reply, uint32_t flags) {
  assert(binder && data);
  return binder->transact(code, *data, reply, flags);
}

sp<IServiceManager>* DefaultServiceManager() {
  return new sp(defaultServiceManager());
}

void StartThreadPool() {
  ProcessState::self()->startThreadPool();
}
void GiveThreadPoolName() {
  ProcessState::self()->giveThreadPoolName();
}
void FlushCommands() {
  IPCThreadState::self()->flushCommands();
}

status_t IBinder_transact(IBinder* binder, uint32_t code, const Parcel* data,
                          Parcel* reply, uint32_t flags) {
  assert(binder && data);
  return binder->transact(code, *data, reply, flags);
}
status_t IBinder_linkToDeath(IBinder* binder, const sp<RustDeathRecipient>* recipient,
                             void* cookie, uint32_t flags) {
  assert(binder && recipient);
  return binder->linkToDeath(*recipient, cookie, flags);
}
status_t IBinder_unlinkToDeath(IBinder* binder, const wp<RustDeathRecipient>* recipient,
                               void* cookie, uint32_t flags, wp<IBinder::DeathRecipient>* outPtr) {
  (void) outPtr;
  assert(binder && recipient);
  return binder->unlinkToDeath(*recipient, cookie, flags, 0);
}
sp<IInterface>* IBinder_queryLocalInterface(IBinder* binder, const String16* descriptor) {
  assert(binder && descriptor);
  return new sp(binder->queryLocalInterface(*descriptor));
}
const String16* IBinder_getInterfaceDescriptor(const IBinder* binder) {
  assert(binder);
  return &binder->getInterfaceDescriptor();
}
bool IBinder_isBinderAlive(const IBinder* binder) {
  assert(binder);
  return binder->isBinderAlive();
}
status_t IBinder_pingBinder(IBinder* binder) {
  assert(binder);
  return binder->pingBinder();
}
status_t IBinder_dump(IBinder* binder, int fd, const String16* const* args, size_t args_len) {
  assert(binder);
  Vector<String16> argsVector;
  if (args) {
    for (size_t i = 0; i < args_len; ++i) {
      assert(*args);
      argsVector.push_back(*args[i]);
    }
  }
  return binder->dump(fd, argsVector);
}

status_t IBinder_getExtension(IBinder* binder, sp<IBinder>** out) {
  assert(binder);
  *out = new sp<IBinder>;
  return binder->getExtension(*out);
}
status_t IBinder_getDebugPid(IBinder* binder, pid_t* outPid) {
  assert(binder);
  return binder->getDebugPid(outPid);
}
bool IBinder_checkSubclass(const IBinder* binder, const void* subclassID) {
  assert(binder);
  return binder->checkSubclass(subclassID);
}

Parcel* NewParcel() {
  return new Parcel;
}
status_t Parcel_readStrongBinder(const Parcel* parcel, sp<IBinder>** binder) {
  assert(parcel && binder);
  *binder = new sp<IBinder>;
  return parcel->readStrongBinder(*binder);
}
status_t Parcel_readString8(const Parcel* parcel, String8** string) {
  assert(parcel && string);
  *string = new String8;
  return parcel->readString8(*string);
}
status_t Parcel_readString16(const Parcel* parcel, String16** string) {
  assert(parcel && string);
  *string = new String16;
  return parcel->readString16(*string);
}
status_t Parcel_readBlob(const Parcel* parcel, size_t len, Parcel::ReadableBlob** blob) {
  assert(parcel && blob);
  *blob = new Parcel::ReadableBlob;
  return parcel->readBlob(len, *blob);
}
status_t Parcel_writeBlob(Parcel* parcel, size_t len, bool mutableCopy,
                          Parcel::WritableBlob** blob) {
  assert(parcel && blob);
  *blob = new Parcel::WritableBlob;
  return parcel->writeBlob(len, mutableCopy, *blob);
}
const void* Parcel_ReadableBlob_data(const Parcel::ReadableBlob* blob) {
  assert(blob);
  return blob->data();
}
void* Parcel_WritableBlob_data(Parcel::WritableBlob* blob) {
  assert(blob);
  return blob->data();
}
size_t Parcel_ReadableBlob_size(const Parcel::ReadableBlob* blob) {
  assert(blob);
  return blob->size();
}
size_t Parcel_WritableBlob_size(const Parcel::WritableBlob* blob) {
  assert(blob);
  return blob->size();
}
void Parcel_ReadableBlob_clear(Parcel::ReadableBlob* blob) {
  assert(blob);
  blob->clear();
}
void Parcel_WritableBlob_clear(Parcel::WritableBlob* blob) {
  assert(blob);
  blob->clear();
}
void Parcel_ReadableBlob_release(Parcel::ReadableBlob* blob) {
  assert(blob);
  blob->release();
}
void Parcel_WritableBlob_release(Parcel::WritableBlob* blob) {
  assert(blob);
  blob->release();
}
void Parcel_ReadableBlob_Destructor(Parcel::ReadableBlob* blob) {
  delete blob;
}
void Parcel_WritableBlob_Destructor(Parcel::WritableBlob* blob) {
  delete blob;
}


void IServiceManager_listServices(IServiceManager* self, int dumpsysFlags,
                                  ListServiceCallback* callback, void* context) {
  assert(self && outServices);
  auto services = self->listServices(dumpsysFlags);
  for (auto &service : services) {
    callback(&service, context);
  }
}
const String16* IServiceManager_getInterfaceDescriptor(const IServiceManager* self) {
  assert(self);
  return &self->getInterfaceDescriptor();
}
sp<IBinder>* IServiceManager_getService(const IServiceManager* self, const String16* name) {
  assert(self && name);
  return new sp(self->getService(*name));
}
sp<IBinder>* IServiceManager_checkService(const IServiceManager* self, const String16* name) {
  assert(self && name);
  return new sp(self->checkService(*name));
}
status_t IServiceManager_addService(IServiceManager* self, const String16* name,
                                    const sp<IBinder>* service, bool allowIsolated,
                                    int dumpsysFlags) {
  assert(self && name && service);
  return self->addService(*name, *service, allowIsolated, dumpsysFlags);
}
sp<IBinder>* IServiceManager_waitForService(IServiceManager* self, const String16* name) {
  assert(self && name);
  return new sp(self->waitForService(*name));
}
bool IServiceManager_isDeclared(IServiceManager* self, const String16* name) {
  assert(self && name);
  return self->isDeclared(*name);
}

String8* NewString8() {
  return new String8;
}
String8* NewString8FromUtf16(const char16_t* data, size_t len) {
  return new String8(data, len);
}
String8* NewString8FromUtf8(const char* data, size_t len) {
  return new String8(data, len);
}
const char* String8_data(const String8* S) {
  assert(S);
  return S->string();
}
void String8_Destroy(String8* S) {
  delete S;
}

String16* NewString16() {
  return new String16;
}
String16* CopyString16(const String16 *S) {
  assert(S);
  return new String16(*S);
}
String16* NewString16FromUtf16(const char16_t* data, size_t len) {
  return new String16(data, len);
}
String16* NewString16FromUtf8(const char* data, size_t len) {
  return new String16(data, len);
}
const char16_t* String16_data(const String16* S) {
  assert(S);
  return S->string();
}
void String16_Destroy(String16* S) {
  delete S;
}

base::unique_fd* NewUniqueFd() {
  return new base::unique_fd();
}

void UniqueFd_reset(base::unique_fd* self, int newValue) {
  assert(self);
  self->reset(newValue);
}

void UniqueFd_destructor(base::unique_fd* self) {
  delete self;
}

class RustDeathRecipient: public IBinder::DeathRecipient {
 public:
  RustDeathRecipient(RustObject* object, BinderDiedCallback* binderDied, DestructCallback* destruct)
    : mObject(object), mBinderDiedCallback(binderDied), mDestructCallback(destruct) {}

 protected:
  void binderDied(const wp<IBinder>& who) {
    mBinderDiedCallback(mObject, new wp(who));
  }

  virtual ~RustDeathRecipient() {
    mDestructCallback(mObject);
  }

 private:
  // Rust remotable object
  RustObject* mObject;
  BinderDiedCallback* mBinderDiedCallback;
  DestructCallback* mDestructCallback;
};

sp<RustDeathRecipient>* NewRustDeathRecipient(RustObject* object, BinderDiedCallback* binderDied, DestructCallback* destruct) {
  return new sp(new RustDeathRecipient(object, binderDied, destruct));
}

void Sp_DropRustDeathRecipient(sp<RustDeathRecipient>* sp) {
  delete sp;
}

void Wp_DropRustDeathRecipient(wp<RustDeathRecipient>* wp) {
  delete wp;
}

void Wp_DropRustBBinder(wp<RustBBinder>* wp) {
  delete wp;
}

} // namespace c_interface

} // namespace android
