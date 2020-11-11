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
#include <thread>

#include <android-base/logging.h>
#include <BnBinderRpcSession.h>
#include <BnBinderRpcTest.h>
#include <android-base/logging.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/RpcConnection.h>
#include <binder/RpcServer.h>
#include <gtest/gtest.h>

#include "../RpcState.h" // for debugging

namespace android {

using android::binder::Status;

static const String16 kServiceName = String16("binderRpcTest-binder-server");

#define EXPECT_OK(status) \
  do { \
    Status stat = (status); \
    EXPECT_TRUE(stat.isOk()) << stat; \
  } while(false)

class MyBinderRpcSession : public BnBinderRpcSession {
public:
    static std::atomic<int32_t> gNum;

    MyBinderRpcSession(const std::string& name) : mName(name) {
        gNum++;
    }
    Status getName(std::string* name) override {
        *name = mName;
        return Status::ok();
    }
    ~MyBinderRpcSession() {
        gNum--;
    }
private:
    std::string mName;
};
std::atomic<int32_t> MyBinderRpcSession::gNum;

class MyBinderRpcTest : public BnBinderRpcTest {
public:
    sp<RpcConnection> connection;

    Status sendString(const std::string& str) override {
        std::cout << "Child received string: " << str << std::endl;
        return Status::ok();
    }
    Status doubleString(const std::string& str, std::string* strstr) override {
        std::cout << "Child received string: " << str << std::endl;
        *strstr = str + str;
        return Status::ok();
    }
    Status countBinders(int32_t* out) override {
        if (connection == nullptr) {
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        *out = connection->state()->countBinders();
        if (*out != 1) {
            connection->state()->dump();
        }
        return Status::ok();
    }
    Status pingMe(const sp<IBinder>& binder, int32_t* out) override {
        if (binder == nullptr) {
            std::cout << "Received null binder!" << std::endl;
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        *out = binder->pingBinder();
        return Status::ok();
    }
    Status repeatBinder(const sp<IBinder>& binder, sp<IBinder>* out) override {
        *out = binder;
        return Status::ok();
    }
    Status nestMe(const sp<IBinderRpcTest>& binder, int count) override {
        if (count <= 0) return Status::ok();
        return binder->nestMe(this, count - 1);
    }
    Status openSession(const std::string& name, sp<IBinderRpcSession>* out) override {
        *out = new MyBinderRpcSession(name);
        return Status::ok();
    }
    Status getNumOpenSessions(int32_t* out) override {
        *out = MyBinderRpcSession::gNum;
        return Status::ok();
    }
};

static sp<RpcConnection> gConnection;
static sp<RpcConnection> gConnectionOther;

class BinderRpc : public ::testing::Test {
public:
    void SetUp() override {
        ASSERT_NE(nullptr, gConnection);
        binder = gConnection->getRootObject();
        EXPECT_NE(nullptr, binder);
        iface = interface_cast<IBinderRpcTest>(binder);

        ASSERT_NE(nullptr, gConnectionOther);
        otherBinder = gConnectionOther->getRootObject();
        EXPECT_NE(nullptr, otherBinder);
        otherIface = interface_cast<IBinderRpcTest>(otherBinder);

        actualBinder = defaultServiceManager()->checkService(kServiceName);
        EXPECT_NE(nullptr, actualBinder);
        actualIface = interface_cast<IBinderRpcTest>(actualBinder);
    }
    void TearDown() override {
        EXPECT_EQ(0, MyBinderRpcSession::gNum);

        int32_t remoteBinders;
        EXPECT_OK(iface->countBinders(&remoteBinders));
        // should only be the root binder object, iface
        EXPECT_EQ(remoteBinders, 1);

        EXPECT_OK(otherIface->countBinders(&remoteBinders));
        // should only be the root binder object, iface
        EXPECT_EQ(remoteBinders, 1);

        binder = nullptr;
        iface = nullptr;
        EXPECT_EQ(0, gConnection->state()->countBinders()) << (gConnection->state()->dump(), "dump:");

        otherBinder = nullptr;
        otherIface = nullptr;
        EXPECT_EQ(0, gConnectionOther->state()->countBinders()) << (gConnectionOther->state()->dump(), "dump:");
    }

    // the service as viewed over a socket connection
    sp<IBinder> binder;
    sp<IBinderRpcTest> iface;

    // another service from the same process as viewed over a socket connection
    sp<IBinder> otherBinder;
    sp<IBinderRpcTest> otherIface;

    // the service as viewed over /dev/binder
    sp<IBinder> actualBinder;
    sp<IBinderRpcTest> actualIface;
};

TEST_F(BinderRpc, DidntBreakRegularBinder) {
    EXPECT_EQ(OK, actualBinder->pingBinder());
}

TEST_F(BinderRpc, Ping) {
    EXPECT_EQ(OK, binder->pingBinder());
}

TEST_F(BinderRpc, PingOther) {
    EXPECT_EQ(OK, otherBinder->pingBinder());
}

TEST_F(BinderRpc, TransactionsMustBeMarkedRpc) {
    Parcel data;
    Parcel reply;
    EXPECT_EQ(BAD_TYPE, binder->transact(IBinder::PING_TRANSACTION, data, &reply, 0));
}

TEST_F(BinderRpc, UnknownTransaction) {
    Parcel data;
    data.setAttachedBinder(binder);
    Parcel reply;
    EXPECT_EQ(UNKNOWN_TRANSACTION, binder->transact(1337, data, &reply, 0));
}

TEST_F(BinderRpc, SendSomethingOneway) {
    EXPECT_OK(iface->sendString("asdf"));
}

TEST_F(BinderRpc, SendAndGetResultBack) {
    std::string doubled;
    EXPECT_OK(iface->doubleString("cool ", &doubled));
    EXPECT_EQ("cool cool ", doubled);
}

TEST_F(BinderRpc, SendAndGetResultBackBig) {
    std::string single = std::string(1024, 'a');
    std::string doubled;
    EXPECT_OK(iface->doubleString(single, &doubled));
    EXPECT_EQ(single + single, doubled);
}

// FIXME: test multiple servers/connections to the same process
// FIXME: test chained/layer connections (passing binder through procs
// a->b->c->a
// FIXME: test that oneway ordering guarantees are preserved on mutli-threaded
// connections
// FIXME: test for FD leaks

TEST_F(BinderRpc, CallMeBack) {
    int32_t pingResult;
    EXPECT_OK(iface->pingMe(new MyBinderRpcSession("foo"), &pingResult));
    EXPECT_EQ(OK, pingResult);
}

TEST_F(BinderRpc, RepeatBinder) {
    sp<IBinder> inBinder = new MyBinderRpcSession("foo");
    sp<IBinder> outBinder;
    EXPECT_OK(iface->repeatBinder(inBinder, &outBinder));
    EXPECT_EQ(inBinder, outBinder);

    wp<IBinder> weak = inBinder;
    inBinder = nullptr;
    outBinder = nullptr;

    // FIXME: this is to force reading a reply, which as a side effect
    // will read all the pending dec refs from the other process
    EXPECT_EQ(OK, binder->pingBinder());

    EXPECT_EQ(nullptr, weak.promote());
}

// START TESTS FOR LIMITATIONS OF SOCKET BINDER
// These are behavioral differences form regular binder, where certain usecases
// aren't supported.

TEST_F(BinderRpc, CannotMixBindersBetweenUnrelatedSocketConnections) {
    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION, iface->repeatBinder(otherBinder, &outBinder).transactionError());
}

TEST_F(BinderRpc, CannotSendRegularBinderOverSocketBinder) {
    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION, iface->repeatBinder(actualBinder, &outBinder).transactionError());
}

TEST_F(BinderRpc, CannotSendSocketBinderOverRegularBinder) {
    // FIXME: this should fail, and currently crashes (need to fix handle API)
    // sp<IBinder> outBinder;
    // EXPECT_OK(actualIface->repeatBinder(binder, &outBinder));
}

// END TESTS FOR LIMITATIONS OF SOCKET BINDER

TEST_F(BinderRpc, RepeatRootObject) {
    sp<IBinder> outBinder;
    EXPECT_OK(iface->repeatBinder(binder, &outBinder));
    EXPECT_EQ(binder, outBinder);
}

TEST_F(BinderRpc, NestedTransactions) {
    auto nastyNester = sp<MyBinderRpcTest>::make();
    EXPECT_OK(iface->nestMe(nastyNester, 10));

    wp<IBinder> weak = nastyNester;
    nastyNester = nullptr;
    EXPECT_EQ(nullptr, weak.promote());
}

#define expectSessions(expected) do { \
        int session; \
        EXPECT_OK(iface->getNumOpenSessions(&session)); \
        EXPECT_EQ(expected, session); \
    } while(false)

TEST_F(BinderRpc, SingleSession) {
    sp<IBinderRpcSession> session;
    EXPECT_OK(iface->openSession("aoeu", &session));
    std::string out;
    EXPECT_OK(session->getName(&out));
    EXPECT_EQ("aoeu", out);

    expectSessions(1);
    session = nullptr;
    expectSessions(0);
}

TEST_F(BinderRpc, ManySessions) {
    std::vector<sp<IBinderRpcSession>> sessions;

    for (size_t i = 0; i < 15; i++) {
        expectSessions(i);
        sp<IBinderRpcSession> session;
        EXPECT_OK(iface->openSession(std::to_string(i), &session));
        sessions.push_back(session);
    }
    expectSessions(sessions.size());
    for (size_t i = 0; i < sessions.size(); i++) {
        std::string out;
        EXPECT_OK(sessions.at(i)->getName(&out));
        EXPECT_EQ(std::to_string(i), out);
    }
    expectSessions(sessions.size());

    while (!sessions.empty()) {
        sessions.pop_back();
        expectSessions(sessions.size());
    }
    expectSessions(0);
}

extern "C" int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    android::base::InitLogging(argv, android::base::StderrLogger, android::base::DefaultAborter);

    const char* kSock1 = "/dev/binderRpcTest_socket_1";
    const char* kSock2 = "/dev/binderRpcTest_socket_2";

    // - FIXME - stop using unix domain sockets, or implement some other
    // mechanism to make sure it's not in use
    unlink(kSock1);
    unlink(kSock2);

    pid_t childPid = fork();
    if (childPid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);  // technically racey

        // join as a binder service
        ProcessState::self()->setThreadPoolMaxThreadCount(0);
        defaultServiceManager()->addService(kServiceName, new MyBinderRpcTest);
        ProcessState::self()->startThreadPool();

        // join as a socket service
        std::thread([&]{
            sp<MyBinderRpcTest> service = new MyBinderRpcTest;
            sp<RpcServer> server = RpcServer::makeUnixServer(kSock1);
            service->connection = server->getConnection();
            server->setRootObject(service);
            // FIXME: currently can only join (can't spawn new threads)
            server->join();
            service->connection = nullptr;
        }).detach();

        // join as a socket service (again)
        //
        // This is testing the same server serving multiple services, or a
        // client accessing a service from multiple different sources.
        sp<MyBinderRpcTest> service = new MyBinderRpcTest;
        sp<RpcServer> server2 = RpcServer::makeUnixServer(kSock2);
        service->connection = server2->getConnection();
        server2->setRootObject(service);
        server2->join();
        service->connection = nullptr;

        return EXIT_FAILURE;
    }

    // FIXME
    usleep(10000); // time for connection to be created (might be refused) ?

    // FIXME: this connection should be automatically created in the background
    // by whatever method we get ahold of a server.
    gConnection = RpcConnection::connect(kSock1);
    gConnectionOther = RpcConnection::connect(kSock2);

    std::cout << "This pid: " << getpid() << std::endl;
    std::cout << "Child pid: " << childPid << std::endl;

    int ret = RUN_ALL_TESTS();
    gConnection->state()->dump();
    gConnection = nullptr;
    usleep(100000); // time for logs
    return ret;
}

}  // namespace android
