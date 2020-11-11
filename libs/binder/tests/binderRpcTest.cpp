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
#include <binder/BrBinder.h>
#include <binder/Binder.h>

using namespace android;
// FIXME: convert to more of a gtest-style test

const char* kSock = "/dev/some_socket";

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
        int id = server->addServedBinder(new BBinder());
        std::cout << "Child server ID: " << id << std::endl;
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
    sp<IBinder> binder = new BrBinder(connection, 0 /* FIXME: first ID is 0 in a server pool */);
    std::cout << "Ping: " << binder->pingBinder() << std::endl;

    usleep(100000); // give server time to process

    return EXIT_SUCCESS;
}

