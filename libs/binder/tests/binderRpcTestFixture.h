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

#pragma once

#include <gtest/gtest.h>

#include "binderRpcTestCommon.h"

#define EXPECT_OK(status)                        \
    do {                                         \
        android::binder::Status stat = (status); \
        EXPECT_TRUE(stat.isOk()) << stat;        \
    } while (false)

namespace android {

// Abstract base class with a virtual destructor that handles the
// ownership of a process session for BinderRpcTestSession below
class ProcessSessionBase {
public:
    struct SessionInfo {
        sp<RpcSession> session;
        sp<IBinder> root;
    };

    // client session objects associated with other process
    // each one represents a separate session
    std::vector<SessionInfo> sessions;

    // Trusty services are persistent and never shut down
    bool serverSupportsShutdown = true;

    virtual ~ProcessSessionBase() = 0;
};

// Process session where the process hosts IBinderRpcTest, the server used
// for most testing here
template <typename ProcessSession>
struct BinderRpcTestProcessSession {
    std::unique_ptr<ProcessSession> proc;

    // pre-fetched root object (for first session)
    sp<IBinder> rootBinder;

    // pre-casted root object (for first session)
    sp<IBinderRpcTest> rootIface;

    // whether session should be invalidated by end of run
    bool expectAlreadyShutdown = false;

    BinderRpcTestProcessSession(BinderRpcTestProcessSession&&) = default;
    ~BinderRpcTestProcessSession() {
        if (!expectAlreadyShutdown) {
            EXPECT_NE(nullptr, rootIface);
            if (rootIface == nullptr) return;

            std::vector<int32_t> remoteCounts;
            // calling over any sessions counts across all sessions
            EXPECT_OK(rootIface->countBinders(&remoteCounts));
            if (proc->serverSupportsShutdown) {
                EXPECT_EQ(remoteCounts.size(), proc->sessions.size());
                for (auto remoteCount : remoteCounts) {
                    EXPECT_EQ(remoteCount, 1);
                }

                // even though it is on another thread, shutdown races with
                // the transaction reply being written
                if (auto status = rootIface->scheduleShutdown(); !status.isOk()) {
                    EXPECT_EQ(DEAD_OBJECT, status.transactionError()) << status;
                }
            }
        }

        rootIface = nullptr;
        rootBinder = nullptr;
    }
};

template <typename ProcessSession>
class BinderRpcImpl : public ::testing::TestWithParam<
                              std::tuple<SocketType, RpcSecurity, uint32_t, uint32_t, bool, bool>> {
public:
    SocketType socketType() const { return std::get<0>(GetParam()); }
    RpcSecurity rpcSecurity() const { return std::get<1>(GetParam()); }
    uint32_t clientVersion() const { return std::get<2>(GetParam()); }
    uint32_t serverVersion() const { return std::get<3>(GetParam()); }
    bool serverSingleThreaded() const { return std::get<4>(GetParam()); }
    bool noKernel() const { return std::get<5>(GetParam()); }

    bool clientOrServerSingleThreaded() const {
        return !kEnableRpcThreads || serverSingleThreaded();
    }

    // Whether the test params support sending FDs in parcels.
    bool supportsFdTransport() const {
        if (socketType() == SocketType::TIPC) {
            // Trusty does not support file descriptors yet
            return false;
        }
        return clientVersion() >= 1 && serverVersion() >= 1 && rpcSecurity() != RpcSecurity::TLS &&
                (socketType() == SocketType::PRECONNECTED || socketType() == SocketType::UNIX ||
                 socketType() == SocketType::UNIX_BOOTSTRAP);
    }

    void SetUp() override {
        if (socketType() == SocketType::UNIX_BOOTSTRAP && rpcSecurity() == RpcSecurity::TLS) {
            GTEST_SKIP() << "Unix bootstrap not supported over a TLS transport";
        }
    }

    BinderRpcTestProcessSession<ProcessSession> createRpcTestSocketServerProcess(
            const BinderRpcOptions& options) {
        BinderRpcTestProcessSession<ProcessSession> ret{
                .proc = createRpcTestSocketServerProcessEtc<ProcessSession>(options),
        };

        ret.rootBinder = ret.proc->sessions.empty() ? nullptr : ret.proc->sessions.at(0).root;
        ret.rootIface = interface_cast<IBinderRpcTest>(ret.rootBinder);

        return ret;
    }

    static std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info);

protected:
    // Let BinderRpcImpl<ProcessSessionBase> make calls to
    // createRpcTestSocketServerProcessEtc() for the derived type
    friend class BinderRpcImpl<ProcessSessionBase>;

    template <typename U>
    static std::unique_ptr<U> createRpcTestSocketServerProcessEtc(const BinderRpcOptions& options);
};

} // namespace android
