/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "RpcTrusty"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransport.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <trusty/tipc.h>
// #define __TRUSTY__
#include <android/binder_libbinder.h>
#include <unistd.h>

namespace android {

using android::base::unique_fd;

sp<RpcSession> RpcTrustyConnectWithSessionInitializer(
        const char* device, const char* port,
        std::function<void(sp<RpcSession>&)> sessionInitializer) {
    auto session = RpcSession::make(RpcTransportCtxFactoryTipcAndroid::make());
    // using the callback to initialize the session
    sessionInitializer(session);
    // LOG(ERROR) << ">>>>>>>>>>>>>>>>>>>inside  RpcTrustyConnectWithSessionInitializer before
    // creating connection";
    auto request = [=] {
        int tipcFd = tipc_connect(device, port);
        usleep(1000);
        LOG(ERROR) << ">>>>>>>>>>>>>>>>>>>inside  RpcTrustyConnectWithSessionInitializer after "
                      "sleeping";
        if (tipcFd < 0) {
            LOG(ERROR) << "Failed to connect to Trusty service. Error code: " << tipcFd;
            return unique_fd();
        }
        return unique_fd(tipcFd);
    };
    // LOG(ERROR) << ">>>>>>>>>>>>>>>>>>>inside  RpcTrustyConnectWithSessionInitializer connection
    // created";
    if (status_t status = session->setupPreconnectedClient(unique_fd{}, request); status != OK) {
        LOG(ERROR) << ">>>>>>>>>>>>>>>>>>Failed to set up Trusty client. Error: "
                   << statusToString(status).c_str();
        return nullptr;
    }
    // LOG(ERROR) << ">>>>>>>>>>>>>>>>>>>inside  RpcTrustyConnectWithSessionInitializer returning
    // session"; LOG(ERROR) << ">>>>>>>>>>>>>>>>>>>inside  RpcTrustyConnectWithSessionInitializer
    // returning session";
    return session;
}

sp<IBinder> RpcTrustyConnect(const char* device, const char* port) {
    auto session = RpcTrustyConnectWithSessionInitializer(device, port, [](auto) {});
    return session->getRootObject();
}

} // namespace android

#ifdef __ANDROID_VENDOR__
#error "This library doesn't compile as a vendor module becuase of its dependency of libbinder_ndk"
#endif

extern "C" {
// struct AIBinder;
// extern "C" AIBinder* AIBinder_fromPlatformBinder(const android::sp<android::IBinder>& binder);

extern "C" AIBinder* rpc_trusty_connect(const char* device, const char* port) {
    auto binder = android::RpcTrustyConnect(device, port);
    return AIBinder_fromPlatformBinder(binder);
}
}