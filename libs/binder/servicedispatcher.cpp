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

#include <sysexits.h>
#include <unistd.h>

#include <iostream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android/os/BnServiceManager.h>
#include <android/os/IServiceManager.h>
#include <binder/IServiceManager.h>
#include <binder/RpcServer.h>

using android::defaultServiceManager;
using android::OK;
using android::RpcServer;
using android::statusToString;
using android::String16;
using android::base::Basename;
using android::base::GetBoolProperty;
using android::base::InitLogging;
using android::base::LogdLogger;
using android::base::LogId;
using android::base::LogSeverity;
using android::base::StdioLogger;
using android::base::StringPrintf;

namespace {

using ServiceRetriever = decltype(&android::IServiceManager::checkService);

int Usage(const char* program) {
    auto basename = Basename(program);
    auto format = R"(dispatch calls to RPC service.
Usage:
  %s <service_name>
    <service_name>: the service to connect to.
  %s -m
    Runs an RPC-friendly service that redirects calls to servicemanager.

  If successful, writes port number and a new line character to stdout, and
  blocks until killed.
  Otherwise, writes error message to stderr and exits with non-zero code.
)";
    LOG(ERROR) << StringPrintf(format, basename.c_str(), basename.c_str());
    return EX_USAGE;
}

int Dispatch(const char* name, const ServiceRetriever& serviceRetriever) {
    auto sm = defaultServiceManager();
    if (nullptr == sm) {
        LOG(ERROR) << "No servicemanager";
        return EX_SOFTWARE;
    }
    auto binder = std::invoke(serviceRetriever, defaultServiceManager(), String16(name));
    if (nullptr == binder) {
        LOG(ERROR) << "No service \"" << name << "\"";
        return EX_SOFTWARE;
    }
    auto rpcServer = RpcServer::make();
    if (nullptr == rpcServer) {
        LOG(ERROR) << "Cannot create RpcServer";
        return EX_SOFTWARE;
    }
    rpcServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    unsigned int port;
    if (!rpcServer->setupInetServer(0, &port)) {
        LOG(ERROR) << "setupInetServer failed";
        return EX_SOFTWARE;
    }
    auto socket = rpcServer->releaseServer();
    auto status = binder->setRpcClientDebug(std::move(socket));
    if (status != OK) {
        LOG(ERROR) << "setRpcClientDebug failed with " << statusToString(status);
        return EX_SOFTWARE;
    }
    LOG(INFO) << "Finish setting up RPC on service " << name << " on port " << port;

    std::cout << port << std::endl;
    return EX_OK;
}

// Wrapper that wraps a BpServiceManager as a BnServiceManager.
class ServiceManagerProxyToNative : public android::os::BnServiceManager {
public:
    ServiceManagerProxyToNative(const sp<android::os::IServiceManager>& impl) : mImpl(impl) {}
    android::binder::Status getService(const std::string&,
                                       android::sp<android::IBinder>*) override {
        // We can't send BpBinder over RPC.
        return android::binder::Status::fromStatusT(android::INVALID_OPERATION);
    }
    android::binder::Status checkService(const std::string&,
                                         android::sp<android::IBinder>*) override {
        // We can't send BpBinder over RPC.
        return android::binder::Status::fromStatusT(android::INVALID_OPERATION);
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

int wrapServiceManager(const ServiceRetriever& serviceRetriever) {
    auto sm = defaultServiceManager();
    if (nullptr == sm) {
        LOG(ERROR) << "No servicemanager";
        return EX_SOFTWARE;
    }
    auto service = std::invoke(serviceRetriever, defaultServiceManager(), String16("manager"));
    if (nullptr == service) {
        LOG(ERROR) << "No service called `manager`";
        return EX_SOFTWARE;
    }
    auto interface = android::os::IServiceManager::asInterface(service);
    if (nullptr == interface) {
        LOG(ERROR) << "Cannot cast service called `manager` to IServiceManager";
        return EX_SOFTWARE;
    }

    // Work around restriction that doesn't allow us to send proxy over RPC.
    interface = sp<ServiceManagerProxyToNative>::make(interface);
    service = ServiceManagerProxyToNative::asBinder(interface);

    auto rpcServer = RpcServer::make();
    rpcServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    rpcServer->setRootObject(service);
    unsigned int port;
    if (!rpcServer->setupInetServer(0, &port)) {
        LOG(ERROR) << "Unable to set up inet server";
        return EX_SOFTWARE;
    }
    LOG(INFO) << "Finish wrapping servicemanager with RPC on port " << port;
    std::cout << port << std::endl;
    rpcServer->join();

    LOG(FATAL) << "Wrapped servicemanager exits; this should not happen!";
    __builtin_unreachable();
}

// Log to logd. For warning and more severe messages, also log to stderr.
class ServiceDispatcherLogger {
public:
    void operator()(LogId id, LogSeverity severity, const char* tag, const char* file,
                    unsigned int line, const char* message) {
        mLogdLogger(id, severity, tag, file, line, message);
        if (severity >= LogSeverity::WARNING) {
            std::cout << std::flush;
            std::cerr << Basename(getprogname()) << ": " << message << std::endl;
        }
    }

private:
    LogdLogger mLogdLogger{};
};

} // namespace

int main(int argc, char* argv[]) {
    InitLogging(argv, ServiceDispatcherLogger());

    if (!GetBoolProperty("ro.debuggable", false)) {
        LOG(ERROR) << "servicedispatcher is only allowed on debuggable builds.";
        return EX_NOPERM;
    }
    LOG(WARNING) << "WARNING: servicedispatcher is debug only. Use with caution.";

    int opt;
    bool m = false;
    ServiceRetriever serviceRetriever = &android::IServiceManager::checkService;
    while (-1 != (opt = getopt(argc, argv, "gm"))) {
        switch (opt) {
            case 'g': {
                serviceRetriever = &android::IServiceManager::getService;
            } break;
            case 'm': {
                m = true;
            } break;
            default: {
                return Usage(argv[0]);
            }
        }
    }

    if (m) {
        if (optind != argc) return Usage(argv[0]);
        return wrapServiceManager(serviceRetriever);
    }

    if (optind + 1 != argc) return Usage(argv[0]);
    auto name = argv[optind];

    return Dispatch(name, serviceRetriever);
}
