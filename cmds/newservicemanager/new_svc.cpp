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

#define LOG_TAG     "NewServiceManager"

#include "new_svc.h"
#include <unistd.h>
#include <cerrno>
#include <iostream>
#include <vector>
#include <sys/types.h>
#include <utils/Log.h>
#include <utils/threads.h>

using namespace android;

// TODO search handle and remove from the service list
void DeadService::binderDied(const wp<IBinder>& /* who */) {
  ALOGE("Service died\n");
}

ServiceInfo* ServiceManager::findService(const String16& name) const {
  if (service_list_.empty()) {
    return nullptr;
  }
  for (std::vector<ServiceInfo*>::const_iterator srv_it = service_list_.begin();
       srv_it != service_list_.end(); ++srv_it) {
    if ((*srv_it)->name_ == name) {
      return static_cast<ServiceInfo*>((*srv_it));
    }
  }
  return nullptr;
}

Vector<String16> ServiceManager::listServices() {
  Vector<String16> list;

  ALOGV("List services\n");
  for (std::vector<ServiceInfo*>::const_iterator srv_it = service_list_.begin();
       srv_it != service_list_.end(); ++srv_it) {
    list.add((*srv_it)->name_);
    ALOGV("\t%s\n", String8((*srv_it)->name_).string());
  }
  return list;
}

sp<IBinder> ServiceManager::getService(const String16& name) const {
  ALOGV("Get service %s\n", String8(name).string());
  ServiceInfo* svc = findService(name);
  if (svc) {
    return svc->handle_;
  }
  return nullptr;
}

sp<IBinder> ServiceManager::checkService(const String16& name) const {
  ALOGV("Check service %s\n", String8(name).string());
  ServiceInfo* svc = findService(name);
  if (svc) {
    return svc->handle_;
  }
  return nullptr;
}

status_t ServiceManager::addService(const String16& name, const sp<IBinder>& service,
                                    bool allow_isolated) {
  if (service == nullptr) {
    return INVALID_OPERATION;
  }

  ServiceInfo* svc = findService(name);
  {
    AutoMutex lock(mutex_);
    if (svc) {
      ALOGV("Service allready registered\n");
      svc->handle_ = service;
    } else {
      svc = new ServiceInfo(name, service, allow_isolated);
      service_list_.push_back(svc);
      ALOGV("Adding new service %s\n", String8(name).string());
    }
  }

  service->remoteBinder()->incStrongHandle();
  sp<DeadService> rip = new DeadService();
  service->linkToDeath(rip);
  IPCThreadState* ipc = IPCThreadState::self();
  ipc->flushCommands();
  return NO_ERROR;
}

// TODO: Find a better approach.
void infiniteSleep() {
  while (true) {
    sleep(kMaxSleepTime);
  }
}

int main(void) {
  sp<ProcessState> proc(ProcessState::self());
  // TODO: Add SELinux hook.
  if (!proc->becomeContextManager(nullptr, nullptr)) {
    ALOGE("Failed to become context manager\n");
    return ALREADY_EXISTS;
  }
  proc->setTheContextObject(new ServiceManager());
  proc->startThreadPool();
  infiniteSleep();

  return NO_ERROR;
}
