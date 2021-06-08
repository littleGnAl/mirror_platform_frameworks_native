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
#include <binder/IServiceManager.h>
#include <binder/RpcServer.h>
#include <utils/Errors.h>

using android::DEAD_OBJECT;
using android::defaultServiceManager;
using android::IBinder;
using android::NO_INIT;
using android::OK;
using android::RpcServer;
using android::sp;
using android::statusToString;
using android::String16;
using android::base::Basename;
using android::base::GetBoolProperty;
using android::base::GetUintProperty;
using android::base::InitLogging;
using android::base::LogdLogger;
using android::base::LogId;
using android::base::LogSeverity;
using android::base::SetProperty;
using android::base::StdioLogger;
using android::base::StringPrintf;

namespace {
int Usage(const char* program) {
    auto format = R"(dispatch calls to RPC service.
Usage:
  %s [-s] <service_name>
    -s: shuts down RPC communication.
    <service_name>: the service to connect to.
)";
    LOG(ERROR) << StringPrintf(format, Basename(program).c_str());
    return EX_USAGE;
}

std::string GetPropertyKey(const char* name) {
    return StringPrintf("servicedispatcher.%s.port", name);
}

sp<IBinder> FindService(const char* name) {
    auto sm = defaultServiceManager();
    if (nullptr == sm) {
        LOG(ERROR) << "No servicemanager";
        return nullptr;
    }
    auto binder = sm->checkService(String16(name));
    if (nullptr == binder) {
        LOG(ERROR) << "No service \"" << name << "\"";
        return nullptr;
    }
    return binder;
}

int Dispatch(const char* name) {
    auto binder = FindService(name);
    if (nullptr == binder) return EX_SOFTWARE;

    auto propertyKey = GetPropertyKey(name);
    if (auto existing = GetUintProperty<unsigned int>(propertyKey, 0u); existing != 0) {
        LOG(INFO) << "Returning previously set up port for service " << name << ": " << existing;
        std::cout << existing << std::endl;
        return EX_OK;
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
    if (!SetProperty(propertyKey, std::to_string(port))) {
        LOG(WARNING) << "Unable to set " << propertyKey << " to " << port
                     << ", future calls to servicedispatcher on service " << name << " may fail";
    }
    LOG(INFO) << "Finish setting up RPC on service " << name << " on port" << port;

    std::cout << port << std::endl;
    return EX_OK;
}

int Shutdown(const char* name) {
    auto binder = FindService(name);
    if (nullptr == binder) return EX_SOFTWARE;
    auto status = binder->setRpcClientDebug(android::base::unique_fd());

    // If OK, clear property.
    // If NO_INIT, the service likely did not set up RPC server. Also clear property.
    // If DEAD_OBJECT, the service is dead. Also clear property.
    // Also log accordingly.
    switch (status) {
        case NO_INIT:
        case DEAD_OBJECT:
            LOG(WARNING) << "WARNING: setRpcClientDebug failed with " << statusToString(status);
            [[fallthrough]];
        case OK: {
            auto propertyKey = GetPropertyKey(name);
            if (!SetProperty(propertyKey, "")) {
                LOG(WARNING) << "Unable to set " << propertyKey
                             << " to empty, future calls to servicedispatcher on service " << name
                             << " may fail";
            }
        } break;
        default:
            LOG(ERROR) << "Unable to shutdown RPC on " << name << ": " << statusToString(status)
                       << ". Future calls to servicedispatcher on service " << name << " may fail.";
    }

    // If OK or NO_INIT, RpcServer is properly destroyed. Return OK. Otherwise return error.
    switch (status) {
        case OK:
        case NO_INIT:
            return EX_OK;
        default:
            return EX_SOFTWARE;
    }
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

    bool shutdown = false;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "s"))) {
        switch (opt) {
            case 's': {
                shutdown = true;
            } break;
            default: {
                return Usage(argv[0]);
            }
        }
    }
    if (optind + 1 != argc) return Usage(argv[0]);
    auto name = argv[optind];

    if (shutdown) return Shutdown(name);
    return Dispatch(name);
}
