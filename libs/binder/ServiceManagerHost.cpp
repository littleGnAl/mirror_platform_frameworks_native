/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "ServiceManagerHost.h"

#include <android-base/parseint.h>
#include <android/os/BnServiceManager.h>
#include <binder/RpcSession.h>

#include "Utils.h"

namespace android {

namespace {

const void* kDeviceServiceExtraId = "DeviceServiceExtra";

// RAII object for adb forwarding
class AdbForwarder {
public:
    AdbForwarder() = default;
    static std::optional<AdbForwarder> forward(unsigned int devicePort);
    AdbForwarder(AdbForwarder&& other) noexcept { (*this) = std::move(other); }
    AdbForwarder& operator=(AdbForwarder&&) noexcept;
    ~AdbForwarder();
    [[nodiscard]] const std::optional<unsigned int>& hostPort() const { return mPort; }

private:
    DISALLOW_COPY_AND_ASSIGN(AdbForwarder);
    explicit AdbForwarder(unsigned int port) : mPort(port) {}
    std::optional<unsigned int> mPort;
};
std::optional<AdbForwarder> AdbForwarder::forward(unsigned int devicePort) {
    auto executeResult =
            execute({"adb", "forward", "tcp:0", "tcp:" + std::to_string(devicePort)}, nullptr);
    if (!executeResult.ok()) {
        ALOGE("Unable to run `adb forward tcp:0 tcp:%d`: %s", devicePort,
              executeResult.error().toString().c_str());
        return std::nullopt;
    }
    if (executeResult->exitCode.value_or(1) != 0) { // has_value() && value() == 0
        ALOGE("Unable to run `adb forward tcp:0 tcp:%d`, command exits with %s", devicePort,
              executeResult->toString().c_str());
        return std::nullopt;
    }
    auto hostPortString = executeResult->stdout;
    if (!hostPortString.empty() && hostPortString.back() == '\n')
        hostPortString = hostPortString.substr(0, hostPortString.size() - 1);
    unsigned int hostPort = 0;
    if (!android::base::ParseUint(hostPortString, &hostPort)) {
        ALOGE("Not a valid host port: %s", hostPortString.c_str());
        return std::nullopt;
    }
    if (hostPort == 0) {
        ALOGE("0 is not a valid host port");
        return std::nullopt;
    }
    return AdbForwarder(hostPort);
}

AdbForwarder& AdbForwarder::operator=(AdbForwarder&& other) noexcept {
    std::swap(mPort, other.mPort);
    return *this;
}

AdbForwarder::~AdbForwarder() {
    if (!mPort.has_value()) return;

    auto executeResult =
            execute({"adb", "forward", "--remove", "tcp:" + std::to_string(*mPort)}, nullptr);
    if (!executeResult.ok()) {
        ALOGW("Unable to run `adb forward --remove tcp:%d`: %s", *mPort,
              executeResult.error().toString().c_str());
    }
    if (executeResult->exitCode.value_or(1) != 0) { // has_value() && value() == 0
        ALOGW("Unable to run `adb forward --remove tcp:%d`, command exits with %s", *mPort,
              executeResult->toString().c_str());
    }
    ALOGI("Successfully run `adb forward --remove tcp:%d`", *mPort);
}

struct DeviceServiceExtra {
    static void cleanup(const void* id, void* obj, void* cookie);

    CommandResult commandResult;
    AdbForwarder adbForwarder;
};
void DeviceServiceExtra::cleanup(const void* id, void* obj, void* /* cookie */) {
    LOG_ALWAYS_FATAL_IF(id != kDeviceServiceExtraId,
                        "DeviceServiceExtra::cleanup invoked with mismatched ID %p, "
                        "expected %p",
                        id, kDeviceServiceExtraId);
    auto ptr = reinterpret_cast<DeviceServiceExtra*>(obj);
    delete ptr;
}

// Get a service on device by running servicedispatcher with the given args, e.g.
//     getDeviceService({"adb", "shell", "servicedispatcher", "foo"});
// Return nullptr on any error.
// When the returned binder object is destroyed, remove adb forwarding and kills
// the long-running servicedispatcher process.
sp<IBinder> getDeviceService(std::vector<std::string> serviceDispatcherArgs) {
    auto extra = std::make_unique<DeviceServiceExtra>();

    auto executeResult =
            execute(std::move(serviceDispatcherArgs), &CommandResult::stdoutEndsWithNewLine);
    if (!executeResult.ok()) {
        ALOGE("%s", executeResult.error().toString().c_str());
        return nullptr;
    }

    extra->commandResult = std::move(*executeResult);
    if (extra->commandResult.exitCode.value_or(0) != 0) { // !has_value() || value() == 0
        ALOGE("Command exits with: %s", extra->commandResult.toString().c_str());
        return nullptr;
    }
    if (!extra->commandResult.stdoutEndsWithNewLine()) {
        ALOGE("Unexpected command result: %s", extra->commandResult.toString().c_str());
        return nullptr;
    }

    std::string devicePortString =
            extra->commandResult.stdout.substr(0, extra->commandResult.stdout.size() - 1);
    unsigned int devicePort = 0;
    if (!android::base::ParseUint(devicePortString, &devicePort)) {
        int savedErrno = errno;
        ALOGE("Not a valid device port number: %s: %s", devicePortString.c_str(),
              strerror(savedErrno));
        return nullptr;
    }
    if (devicePort == 0) {
        ALOGE("Not a valid device port number: 0");
        return nullptr;
    }

    auto forwardResult = AdbForwarder::forward(devicePort);
    if (!forwardResult.has_value()) {
        return nullptr;
    }
    extra->adbForwarder = std::move(*forwardResult);
    LOG_ALWAYS_FATAL_IF(!extra->adbForwarder.hostPort().has_value());

    auto rpcSession = RpcSession::make();
    if (!rpcSession->setupInetClient("127.0.0.1", *extra->adbForwarder.hostPort())) {
        ALOGE("Unable to set up inet client on host port %u", *extra->adbForwarder.hostPort());
        return nullptr;
    }
    auto binder = rpcSession->getRootObject();
    if (binder == nullptr) {
        ALOGE("RpcSession::getRootObject returns nullptr");
        return nullptr;
    }
    binder->attachObject(kDeviceServiceExtraId, reinterpret_cast<void*>(extra.release()), nullptr,
                         &DeviceServiceExtra::cleanup);
    return binder;
}

// Wraps a RPC service manager, replacing getService / checkService that uses servicedispatcher
// directly.
class ServiceManagerHost : public android::os::BnServiceManager {
public:
    explicit ServiceManagerHost(const sp<android::os::IServiceManager>& impl) : mImpl(impl) {}
    android::binder::Status getService(const std::string& name,
                                       android::sp<android::IBinder>* _aidl_return) override {
        *_aidl_return = getDeviceService({"adb", "shell", "servicedispatcher", "-g", name});
        // returns ok to align with behavior on device
        return android::binder::Status::ok();
    }
    android::binder::Status checkService(const std::string& name,
                                         android::sp<android::IBinder>* _aidl_return) override {
        *_aidl_return = getDeviceService({"adb", "shell", "servicedispatcher", name});
        // returns ok to align with behavior on device
        return android::binder::Status::ok();
    }
    android::binder::Status addService(const std::string& name,
                                       const android::sp<android::IBinder>& service,
                                       bool allowIsolated, int32_t dumpPriority) override {
        return mImpl->addService(name, service, allowIsolated, dumpPriority);
    }
    android::binder::Status listServices(int32_t dumpPriority,
                                         std::vector<std::string>* _aidl_return) override {
        return mImpl->listServices(dumpPriority, _aidl_return);
    }
    android::binder::Status registerForNotifications(
            const std::string& name,
            const android::sp<android::os::IServiceCallback>& callback) override {
        return mImpl->registerForNotifications(name, callback);
    }
    android::binder::Status unregisterForNotifications(
            const std::string& name,
            const android::sp<android::os::IServiceCallback>& callback) override {
        return mImpl->unregisterForNotifications(name, callback);
    }
    android::binder::Status isDeclared(const std::string& name, bool* _aidl_return) override {
        return mImpl->isDeclared(name, _aidl_return);
    }
    android::binder::Status getDeclaredInstances(const std::string& iface,
                                                 std::vector<std::string>* _aidl_return) override {
        return mImpl->getDeclaredInstances(iface, _aidl_return);
    }
    android::binder::Status updatableViaApex(const std::string& name,
                                             std::optional<std::string>* _aidl_return) override {
        return mImpl->updatableViaApex(name, _aidl_return);
    }
    android::binder::Status registerClientCallback(
            const std::string& name, const android::sp<android::IBinder>& service,
            const android::sp<android::os::IClientCallback>& callback) override {
        return mImpl->registerClientCallback(name, service, callback);
    }
    android::binder::Status tryUnregisterService(
            const std::string& name, const android::sp<android::IBinder>& service) override {
        return mImpl->tryUnregisterService(name, service);
    }
    android::binder::Status getServiceDebugInfo(
            std::vector<android::os::ServiceDebugInfo>* _aidl_return) override {
        return mImpl->getServiceDebugInfo(_aidl_return);
    }

private:
    sp<android::os::IServiceManager> mImpl;
};

} // namespace

sp<android::os::IServiceManager> createHostAidlServiceManager() {
    auto binder = getDeviceService({"adb", "shell", "servicedispatcher", "manager"});
    auto impl = android::os::IServiceManager::asInterface(binder);
    if (impl == nullptr) {
        ALOGE("RpcSession::getRootObject returns object that's not IServiceManager");
        return nullptr;
    }
    return sp<ServiceManagerHost>::make(impl);
}

} // namespace android
