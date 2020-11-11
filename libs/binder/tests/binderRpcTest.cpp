/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <unistd.h>
#include <sys/prctl.h>

#include <cstdlib>
#include <iostream>

#include <BnBinderRpcTest.h>
#include <android-base/logging.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>
#include <binder/RpcConnection.h>
#include <binder/RpcServer.h>
#include <binder/RpcState.h>
#include <binder/Stability.h>
#include <gtest/gtest.h>

using android::defaultServiceManager;
using android::BBinder;
using android::BpBinder;
using android::IBinder;
using android::IInterface;
using android::OK;
using android::UNKNOWN_ERROR;
using android::RpcAddress;
using android::RpcConnection;
using android::RpcServer;
using android::RpcState;
using android::binder::Status;
using android::interface_cast;
using android::internal::Stability;
using android::sp;

// FIXME: only test socket-specific things, other things should be tested in
// aidl_integration_test

const char* kSock = "/dev/some_socket";

#define EXPECT_OK(status) \
  do { \
    Status stat = (status); \
    EXPECT_TRUE(stat.isOk()) << stat; \
  } while(false)

class MyBinderRpcTest : public BnBinderRpcTest {
public:
    Status sendString(const std::string& str) {
        std::cout << "Child received string: " << str << std::endl;
        return Status::ok();
    }
    Status doubleString(const std::string& str, std::string* strstr) {
        std::cout << "Child received string: " << str << std::endl;
        *strstr = str + str;
        return Status::ok();
    }
    Status pingMe(const sp<IBinder>& binder, int32_t* out) {
        if (binder == nullptr) {
            std::cout << "Received null binder!" << std::endl;
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        *out = UNKNOWN_ERROR; // binder->pingBinder();
        return Status::ok();
    }
    Status repeatBinder(const sp<IBinder>& binder, sp<IBinder>* out) {
        *out = binder;
        return Status::ok();
    }
};

static sp<IBinder> getBinder() {
    // FIXME: this connection should be automatically created in the background
    // by whatever method we get ahold of a server. Currently, we just magically
    // know the address (and the top-level binder is always registered with the
    // first identifier, 0).
    static sp<RpcConnection> connection = RpcConnection::connect(kSock);
    if (connection == nullptr) {
        std::cout << "NULL CONNECTION!!!" << std::endl;
        abort();
    }
    // FIXME: '0' magic to get base binder
    sp<IBinder> binder = RpcState::self().getOrLookupProxy(connection, {0});

    // FIXME: would normally be done when reading parcel from another process,
    // but here we "magically" create a connection, so we don't get this
    // information from a transaction.
    Stability::markCompilationUnit(binder.get());

    return binder;
}
static sp<IBinderRpcTest> getInterface() {
    return interface_cast<IBinderRpcTest>(getBinder());
}

TEST(BinderRpc, DidntBreakRegularBinder) {
    EXPECT_EQ(OK, IInterface::asBinder(defaultServiceManager())->pingBinder());
}

TEST(BinderRpc, Ping) {
    sp<IBinder> binder = getBinder();
    EXPECT_EQ(OK, binder->pingBinder());
}

TEST(BinderRpc, SendSomethingOneway) {
    EXPECT_OK(getInterface()->sendString("asdf"));
}

TEST(BinderRpc, SendAndGetResultBack) {
    std::string doubled;
    EXPECT_OK(getInterface()->doubleString("cool ", &doubled));
    EXPECT_EQ("cool cool ", doubled);
}

// FIXME: add test force write objects to parcel, and make sure it is rejected
// FIXME: add test can't write file descriptor
// FIXME: test multiple servers/connections to the same process
// FIXME: test chained/layer connections (passing binder through procs
// a->b->c->a
// FIXME: test that oneway ordering guarantees are preserved on mutli-threaded
// connections

TEST(BinderRpc, CallMeBack) {
    sp<IBinder> binder = new BBinder;
    int32_t pingResult;
    EXPECT_OK(getInterface()->pingMe(binder, &pingResult));
    EXPECT_EQ(OK, pingResult);
}

TEST(BinderRpc, RepeatBinder) {
    sp<IBinder> binder = new BBinder;
    sp<IBinder> outBinder;
    EXPECT_OK(getInterface()->repeatBinder(binder, &outBinder));
    EXPECT_EQ(binder, outBinder);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    android::base::InitLogging(argv, android::base::StderrLogger, android::base::DefaultAborter);

    // - FIXME - stop using unix domain sockets, or implement some other
    // mechanism to make sure it's not in use
    unlink(kSock);

    pid_t childPid = fork();
    if (childPid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);  // technically racey
        sp<RpcServer> server = RpcServer::makeUnixServer(kSock);
        server->attachServedBinder(new MyBinderRpcTest());
        server->join();
        return EXIT_FAILURE;
    }

    std::cout << "This pid: " << getpid() << std::endl;
    std::cout << "Child pid: " << childPid << std::endl;

    return RUN_ALL_TESTS();
}

