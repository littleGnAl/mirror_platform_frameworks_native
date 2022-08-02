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

#define TLOG_TAG "binderRpcTestService"

#include <inttypes.h>
#include <lib/tipc/tipc.h>
#include <lk/err_ptr.h>
#include <stdio.h>
#include <sys/mman.h>
#include <trusty/sys/mman.h>
#include <trusty_log.h>
#include <uapi/mm.h>

#include <vector>

#include <binder/RpcServerTrusty.h>

#include <binderRpcTestCommon.h>

using android::String16;
using android::binder::Status;

int main(void) {
    TLOGI("Starting service\n");

    tipc_hset* hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("Failed to create handle set (%d)\n", PTR_ERR(hset));
        return EXIT_FAILURE;
    }

    const auto port_acl = android::RpcServerTrusty::PortAcl{
            .flags = IPC_PORT_ALLOW_NS_CONNECT,
    };

    // message size needs to be large enough to cover all messages sent by the
    // tests
    constexpr size_t max_msg_size = 256;
    auto server =
            android::RpcServerTrusty::make(hset, android::kTrustyIpcPort,
                                           std::shared_ptr<const android::RpcServerTrusty::PortAcl>(
                                                   &port_acl),
                                           max_msg_size);
    if (!server.ok()) {
        TLOGE("Failed to create RpcServer (%d)\n", server.error());
        return EXIT_FAILURE;
    }

    (*server)->setPerSessionRootObject([&](const void* /*addrPtr*/, size_t /*len*/) {
        auto service = android::sp<android::MyBinderRpcTest>::make();
        // On Trusty we do not have an RpcServer on purpose
        service->server.clear();
        return service;
    });

    return tipc_run_event_loop(hset);
}
