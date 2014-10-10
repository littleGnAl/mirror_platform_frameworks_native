/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <limits>
#include <vector>

#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>


using namespace android;

static constexpr uint32_t kMaxSleepTime = std::numeric_limits<uint32_t>::max();

class ServiceInfo {
 public:
  explicit ServiceInfo(const String16& name, sp<IBinder> handle, bool allow_isolated) {
    name_ = name;
    handle_ = handle;
    allow_isolated_ = allow_isolated;
  }

  String16 name_;
  sp<IBinder> handle_;
  bool allow_isolated_;
};

class DeadService : public IBinder::DeathRecipient {
 public:
   virtual void binderDied(const wp<IBinder>& who);
};

class ServiceManager : public BnServiceManager {
 public:
   ServiceManager() {
    service_list_.push_back(new ServiceInfo(IServiceManager::getInterfaceDescriptor(), NULL, true));
   }
   ~ServiceManager() {}

  virtual sp<IBinder> getService(const String16& name) const;
  virtual sp<IBinder> checkService(const String16& name) const;
  virtual status_t addService(const String16& name, const sp<IBinder>& service,
                               bool allowIsolated);
  virtual Vector<String16> listServices();

 private:
  ServiceInfo* findService(const String16& name) const;
  std::vector<ServiceInfo*> service_list_;
  Mutex mutex_;
};
