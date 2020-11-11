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

#include <android-base/logging.h>
#include <binder/RpcConnection.h>
#include <binder/RpcServer.h>
#include <binder/BpBinder.h>
#include <binder/Binder.h>
#include <binder/Stability.h>
#include <BnBinderRpcTest.h>

using namespace android;
using namespace android::binder;
// FIXME: convert to more of a gtest-style test
// FIXME: only test socket-specific things, move functionality to
// aidl_integration_test

const char* kSock = "/dev/some_socket";

class MyBinderRpcTest : public BnBinderRpcTest {
public:
    Status sendString(const std::string& str) {
        std::cout << "Child received string: " << str << std::endl;
        return Status::ok();
    }
};

int main(int argc, char** argv) {
    (void) argc; // FIXME
    android::base::InitLogging(argv, android::base::StdioLogger, android::base::DefaultAborter);

    // - FIXME - stop using unix domain sockets, or implement some other
    // mechanism to make sure it's not in use
    unlink(kSock);

    pid_t childPid = fork();
    if (childPid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);  // technically racey
        sp<RpcServer> server = RpcServer::makeUnixServer(kSock);
        server->attachServedBinder(new MyBinderRpcTest());
        // FIXME get id from binder
        // std::cout << "Child server ID: " << id->address << std::endl;
        server->join();
        return EXIT_FAILURE;
    }

    usleep(100000); // give server time to create connection

    std::cout << "This pid: " << getpid() << std::endl;
    std::cout << "Child pid: " << childPid << std::endl;

    sp<RpcConnection> connection = RpcConnection::connect(kSock);
    if (connection == nullptr) {
        std::cout << "NULL CONNECTION!!!" << std::endl;
    }
    const RpcAddress address {0}; // FIXME: magic
    sp<IBinder> binder = BpBinder::create(connection, &address);
    std::cout << "Ping: " << binder->pingBinder() << std::endl;

    // FIXME: would normally be done when reading parcel from another process,
    // but here we "magically" create a connection, so we don't get this
    // information from a transaction.
    internal::Stability::markCompilationUnit(binder.get());

    sp<IBinderRpcTest> test = interface_cast<IBinderRpcTest>(binder);

    std::cout << "Send string result: " << test->sendString("asdf").toString8() << std::endl;

    usleep(100000); // give server time to process

    return EXIT_SUCCESS;
}

