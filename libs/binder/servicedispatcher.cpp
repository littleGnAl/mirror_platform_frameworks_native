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

using android::defaultServiceManager;
using android::IBinder;
using android::OK;
using android::RpcServer;
using android::sp;
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
    LOG(INFO) << "Finish setting up RPC on service " << name << " on port" << port;

    std::cout << port << std::endl;
    return EX_OK;
}

int Shutdown(const char* name) {
    auto binder = FindService(name);
    if (nullptr == binder) return EX_SOFTWARE;
    auto status = binder->setRpcClientDebug(android::base::unique_fd());
    if (status != OK) {
        LOG(ERROR) << "setRpcClientDebug failed with " << statusToString(status);
        return EX_SOFTWARE;
    }
    return EX_OK;
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
