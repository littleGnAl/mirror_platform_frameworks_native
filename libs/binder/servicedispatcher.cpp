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

#ifndef BINDER_RPC_DEV_SERVERS
#error servicedispatcher only allowed on debuggable builds
#endif

#include <stdint.h>
#include <sysexits.h>
#include <unistd.h>

#include <iostream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
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
using android::base::ParseUint;
using android::base::StdioLogger;

namespace {
int Usage(const char* program) {
    auto base = Basename(program);
    LOG(ERROR) << "dispatch calls to RPC service." << std::endl
               << "Usage: " << std::endl
               << "    " << base << " [-n <num_threads>] <service_name>";
    return EX_USAGE;
}

int Dispatch(const char* name, uint32_t num_threads) {
    auto sm = defaultServiceManager();
    if (nullptr == sm) {
        LOG(ERROR) << "No servicemanager";
        return EX_SOFTWARE;
    }
    auto binder = sm->getService(String16(name));
    if (nullptr == binder) {
        LOG(ERROR) << "No service \"" << name << "\"";
        return EX_SOFTWARE;
    }
    auto rpc_server = RpcServer::make();
    if (nullptr == rpc_server) {
        LOG(ERROR) << "Cannot create RpcServer";
        return EX_SOFTWARE;
    }
    rpc_server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    unsigned int port;
    if (!rpc_server->setupInetServer(0, &port)) {
        LOG(ERROR) << "setupInetServer failed";
        return EX_SOFTWARE;
    }
    auto socket = rpc_server->releaseServer();
    auto status = binder->setRpcClientDebug(std::move(socket), num_threads);
    if (status != OK) {
        LOG(ERROR) << "setRpcClientDebug failed with " << statusToString(status);
        return EX_SOFTWARE;
    }
    LOG(INFO) << "Finish setting up RPC on service " << name << " with " << num_threads
              << " threads on port" << port;

    std::cout << port << std::endl;
    return EX_OK;
}

class ServiceDispatcherLogger {
public:
    void operator()(LogId log_id, LogSeverity severity, const char* tag, const char* file,
                    unsigned int line, const char* message) {
        logd_logger_(log_id, severity, tag, file, line, message);
        if (severity >= LogSeverity::ERROR) {
            StdioLogger(log_id, severity, tag, file, line, message);
        }
    }

private:
    LogdLogger logd_logger_{};
};

} // namespace

int main(int argc, char* argv[]) {
    InitLogging(argv, ServiceDispatcherLogger());

    if (!GetBoolProperty("ro.debuggable", false)) {
        LOG(ERROR) << "servicedispatcher is only allowed on debuggable builds.";
        return EX_NOPERM;
    }

    uint32_t num_threads = 5;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "n:"))) {
        switch (opt) {
            case 'n': {
                if (!ParseUint(optarg, &num_threads)) {
                    return Usage(argv[0]);
                }
            } break;
            default: {
                return Usage(argv[0]);
            }
        }
    }
    if (optind >= argc) return Usage(argv[0]);
    auto name = argv[optind++];
    if (optind < argc) return Usage(argv[0]);

    return Dispatch(name, num_threads);
}
