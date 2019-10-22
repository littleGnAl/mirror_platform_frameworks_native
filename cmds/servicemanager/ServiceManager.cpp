/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "ServiceManager.h"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <binder/BpBinder.h>
#include <binder/ProcessState.h>
#include <binder/Stability.h>
#include <cutils/android_filesystem_config.h>
#include <cutils/multiuser.h>
#include <thread>

#ifndef VENDORSERVICEMANAGER
#include <vintf/VintfObject.h>
#include <vintf/constants.h>
#endif  // !VENDORSERVICEMANAGER

using ::android::binder::Status;
using ::android::internal::Stability;

namespace android {

#ifndef VENDORSERVICEMANAGER
static bool isVintfDeclared(const std::string& name) {
    size_t firstSlash = name.find('/');
    size_t lastDot = name.rfind('.', firstSlash);
    if (firstSlash == std::string::npos || lastDot == std::string::npos) {
        LOG(ERROR) << "VINTF HALs require names in the format type/instance (e.g. "
                   << "some.package.foo.IFoo/default) but got: " << name;
        return false;
    }
    const std::string package = name.substr(0, lastDot);
    const std::string iface = name.substr(lastDot+1, firstSlash-lastDot-1);
    const std::string instance = name.substr(firstSlash+1);

    for (const auto& manifest : {
            vintf::VintfObject::GetDeviceHalManifest(),
            vintf::VintfObject::GetFrameworkHalManifest()
        }) {
        if (manifest != nullptr && manifest->hasAidlInstance(package, iface, instance)) {
            return true;
        }
    }
    LOG(ERROR) << "Could not find " << package << "." << iface << "/" << instance
               << " in the VINTF manifest.";
    return false;
}

static bool meetsDeclarationRequirements(const sp<IBinder>& binder, const std::string& name) {
    if (!Stability::requiresVintfDeclaration(binder)) {
        return true;
    }

    return isVintfDeclared(name);
}
#endif  // !VENDORSERVICEMANAGER

ServiceManager::ServiceManager(std::unique_ptr<Access>&& access) : mAccess(std::move(access)) {
#ifndef VENDORSERVICEMANAGER
    // can process these at any times, don't want to delay first VINTF client
    std::thread([] {
        vintf::VintfObject::GetDeviceHalManifest();
        vintf::VintfObject::GetFrameworkHalManifest();
    }).detach();
#endif  // !VENDORSERVICEMANAGER
}
ServiceManager::~ServiceManager() {
    // this should only happen in tests

    for (const auto& [name, callbacks] : mNameToCallback) {
        CHECK(!callbacks.empty()) << name;
        for (const auto& callback : callbacks) {
            CHECK(callback != nullptr) << name;
        }
    }

    for (const auto& [name, service] : mNameToService) {
        CHECK(service.binder != nullptr) << name;
    }
}

Status ServiceManager::getService(const std::string& name, sp<IBinder>* outBinder) {
    *outBinder = tryGetService(name, true);
    // returns ok regardless of result for legacy reasons
    return Status::ok();
}

Status ServiceManager::checkService(const std::string& name, sp<IBinder>* outBinder) {
    *outBinder = tryGetService(name, false);
    // returns ok regardless of result for legacy reasons
    return Status::ok();
}

sp<IBinder> ServiceManager::tryGetService(const std::string& name, bool startIfNotFound) {
    auto ctx = mAccess->getCallingContext();

    sp<IBinder> out;
    if (auto it = mNameToService.find(name); it != mNameToService.end()) {
        const Service& service = it->second;

        if (!service.allowIsolated) {
            uid_t appid = multiuser_get_app_id(ctx.uid);
            bool isIsolated = appid >= AID_ISOLATED_START && appid <= AID_ISOLATED_END;

            if (isIsolated) {
                return nullptr;
            }
        }
        out = service.binder;
    }

    if (!mAccess->canFind(ctx, name)) {
        return nullptr;
    }

    if (!out && startIfNotFound) {
        tryStartService(name);
    }

    return out;
}

bool isValidServiceName(const std::string& name) {
    if (name.size() == 0) return false;
    if (name.size() > 127) return false;

    for (char c : name) {
        if (c == '_' || c == '-' || c == '.' || c == '/') continue;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= '0' && c <= '9') continue;
        return false;
    }

    return true;
}

Status ServiceManager::addService(const std::string& name, const sp<IBinder>& binder, bool allowIsolated, int32_t dumpPriority) {
    auto ctx = mAccess->getCallingContext();

    // apps cannot add services
    if (multiuser_get_app_id(ctx.uid) >= AID_APP) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (binder == nullptr) {
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }

    if (!isValidServiceName(name)) {
        LOG(ERROR) << "Invalid service name: " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }

#ifndef VENDORSERVICEMANAGER
    if (!meetsDeclarationRequirements(binder, name)) {
        // already logged
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }
#endif  // !VENDORSERVICEMANAGER

    // implicitly unlinked when the binder is removed
    if (binder->remoteBinder() != nullptr && binder->linkToDeath(this) != OK) {
        LOG(ERROR) << "Could not linkToDeath when adding " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    mNameToService[name] = Service {
        .binder = binder,
        .allowIsolated = allowIsolated,
        .dumpPriority = dumpPriority,
    };

    auto it = mNameToCallback.find(name);
    if (it != mNameToCallback.end()) {
        for (const sp<IServiceCallback>& cb : it->second) {
            // permission checked in registerForNotifications
            cb->onRegistration(name, binder);
        }
    }

    return Status::ok();
}

Status ServiceManager::listServices(int32_t dumpPriority, std::vector<std::string>* outList) {
    if (!mAccess->canList(mAccess->getCallingContext())) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    size_t toReserve = 0;
    for (auto const& [name, service] : mNameToService) {
        (void) name;

        if (service.dumpPriority & dumpPriority) ++toReserve;
    }

    CHECK(outList->empty());

    outList->reserve(toReserve);
    for (auto const& [name, service] : mNameToService) {
        (void) service;

        if (service.dumpPriority & dumpPriority) {
            outList->push_back(name);
        }
    }

    return Status::ok();
}

Status ServiceManager::registerForNotifications(
        const std::string& name, const sp<IServiceCallback>& callback) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (!isValidServiceName(name)) {
        LOG(ERROR) << "Invalid service name: " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }

    if (callback == nullptr) {
        return Status::fromExceptionCode(Status::EX_NULL_POINTER);
    }

    if (OK != IInterface::asBinder(callback)->linkToDeath(this)) {
        LOG(ERROR) << "Could not linkToDeath when adding " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    mNameToCallback[name].push_back(callback);

    if (auto it = mNameToService.find(name); it != mNameToService.end()) {
        const sp<IBinder>& binder = it->second.binder;

        // never null if an entry exists
        CHECK(binder != nullptr) << name;
        callback->onRegistration(name, binder);
    }

    return Status::ok();
}
Status ServiceManager::unregisterForNotifications(
        const std::string& name, const sp<IServiceCallback>& callback) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    bool found = false;

    auto it = mNameToCallback.find(name);
    if (it != mNameToCallback.end()) {
        removeCallback(IInterface::asBinder(callback), &it, &found);
    }

    if (!found) {
        LOG(ERROR) << "Trying to unregister callback, but none exists " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    return Status::ok();
}

Status ServiceManager::isDeclared(const std::string& name, bool* outReturn) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    *outReturn = false;

#ifndef VENDORSERVICEMANAGER
    *outReturn = isVintfDeclared(name);
#endif
    return Status::ok();
}

void ServiceManager::removeCallback(const wp<IBinder>& who,
                                    CallbackMap::iterator* it,
                                    bool* found) {
    std::vector<sp<IServiceCallback>>& listeners = (*it)->second;

    for (auto lit = listeners.begin(); lit != listeners.end();) {
        if (IInterface::asBinder(*lit) == who) {
            if(found) *found = true;
            lit = listeners.erase(lit);
        } else {
            ++lit;
        }
    }

    if (listeners.empty()) {
        *it = mNameToCallback.erase(*it);
    } else {
        (*it)++;
    }
}

void ServiceManager::binderDied(const wp<IBinder>& who) {
    for (auto it = mNameToService.begin(); it != mNameToService.end();) {
        if (who == it->second.binder) {
            it = mNameToService.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = mNameToCallback.begin(); it != mNameToCallback.end();) {
        removeCallback(who, &it, nullptr /*found*/);
    }
}

void ServiceManager::tryStartService(const std::string& name) {
    ALOGI("Since '%s' could not be found, trying to start it as a lazy AIDL service",
          name.c_str());

    std::thread([=] {
        (void)base::SetProperty("ctl.interface_start", "aidl/" + name);
    }).detach();
}

Status ServiceManager::registerClientCallback(const std::string& name,
                                              const sp<IClientCallback>& cb) {
    if (cb == nullptr) {
        return Status::fromExceptionCode(Status::EX_NULL_POINTER);
    }

    auto ctx = mAccess->getCallingContext();
    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (OK != IInterface::asBinder(cb)->linkToDeath(this)) {
        LOG(ERROR) << "Could not linkToDeath when adding client callback for " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    mNameToClientCallback[name].push_back(cb);

    return Status::ok();
}

ssize_t ServiceManager::Service::getNodeStrongRefCount() {
    sp<BpBinder> bpBinder = binder->remoteBinder();
    if (bpBinder == nullptr) return -1;

    return ProcessState::self()->getStrongRefCountForNodeByHandle(bpBinder->handle());
}

Status ServiceManager::handleClientCallbacks() {
    for (auto it = mNameToService.begin(); it != mNameToService.end(); ++it) {
        handleServiceClientCallback(it->first);
    }

    return Status::ok();
}

ssize_t ServiceManager::handleServiceClientCallback(const std::string& serviceName) {
    if (mNameToService.count(serviceName) < 1 || mNameToClientCallback.count(serviceName) < 1) {
        return -1;
    }

    Service service = mNameToService[serviceName];
    ssize_t count = service.getNodeStrongRefCount();

    // binder driver doesn't support this feature
    if (count == -1) return count;

    bool hasClients = count > 1; // this process holds a strong count

    if (hasClients && !service.mHasClients) {
        // client was retrieved in some other way
        sendClientCallbackNotifications(serviceName, true);
    }

    // there are no more clients, but the callback has not been called yet
    if (!hasClients && service.mHasClients) {
            sendClientCallbackNotifications(serviceName, false);
    }

    return count;
}

void ServiceManager::sendClientCallbackNotifications(const std::string& serviceName, bool hasClients) {
    if (mNameToService.count(serviceName) < 1) {
        LOG(WARNING) << "sendClientCallbackNotifications could not find service " << serviceName;
        return;
    }
    Service& service = mNameToService[serviceName];

    CHECK(hasClients != service.mHasClients) << "Record shows: " << service.mHasClients
        << " so we can't tell clients again that we have client: " << hasClients;

    LOG(INFO) << "Notifying " << serviceName << " they have clients: " << hasClients;

    if (mNameToClientCallback.count(serviceName) < 1) {
        LOG(WARNING) << "sendClientCallbackNotifications could not find callbacks for service "
                << serviceName;
        return;
    }

    for (auto it = mNameToClientCallback[serviceName].begin(); it != mNameToClientCallback[serviceName].end(); ++ it) {
        Status ret = (*it)->onClients(service.binder, hasClients);
    }

    service.mHasClients = hasClients;
}

Status ServiceManager::tryUnregisterService(const std::string& name, const sp<IBinder>& binder) {
    if (binder == nullptr) {
        return Status::fromExceptionCode(Status::EX_NULL_POINTER);
    }

    auto ctx = mAccess->getCallingContext();
    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (mNameToService.count(name) < 1) {
        LOG(WARNING) << "Tried to unregister " << name
            << ", but that service wasn't registered to begin with.";
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    sp<IBinder> storedBinder = mNameToService[name].binder;

    if (binder != storedBinder) {
        LOG(WARNING) << "Tried to unregister " << name
            << ", but a different service is registered under this name.";
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    int clients = handleServiceClientCallback(name);

    // clients < 0: feature not implemented or other error. Assume clients.
    // Otherwise:
    // - kernel driver will hold onto one refcount (during this transaction)
    // - servicemanager has a refcount (guaranteed by this transaction)
    // So, if clients > 2, then at least one other service on the system must hold a refcount.
    if (clients < 0 || clients > 2) {
        // client callbacks are either disabled or there are other clients
        LOG(INFO) << "Tried to unregister " << name << " but there are clients: " << clients;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    removeService(name);

    return Status::ok();
}

void ServiceManager::removeService(const std::string& name) {
    mNameToCallback.erase(name);
    mNameToClientCallback.erase(name);
    mNameToService.erase(name);
}

}  // namespace android