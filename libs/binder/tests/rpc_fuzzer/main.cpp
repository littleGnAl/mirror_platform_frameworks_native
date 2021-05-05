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
#include <fuzzer/FuzzedDataProvider.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>

#include <sys/resource.h>
#include <sys/un.h>

namespace android {

static const std::string kSock = std::string(getenv("TMPDIR") ?: "/tmp") +
        "/binderRpcFuzzerSocket_" + std::to_string(getpid());

size_t getHardMemoryLimit() {
    struct rlimit limit;
    CHECK(0 == getrlimit(RLIMIT_AS, &limit)) << errno;
    return limit.rlim_max;
}

void setMemoryLimit(size_t cur, size_t max) {
    const struct rlimit kLimit = {
            .rlim_cur = cur,
            .rlim_max = max,
    };
    CHECK(0 == setrlimit(RLIMIT_AS, &kLimit)) << errno;
}

class SomeBinder : public BBinder {
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0) {
        (void)flags;

        if ((code & 1) == 0) {
            sp<IBinder> binder;
            (void)data.readStrongBinder(&binder);
            if (binder != nullptr) {
                (void)binder->pingBinder();
            }
        }
        if ((code & 2) == 0) {
            (void)data.readInt32();
        }
        if ((code & 4) == 0) {
            (void)reply->writeStrongBinder(sp<BBinder>::make());
        }

        return OK;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 50000) return 0;

    unlink(kSock.c_str());

    sp<RpcServer> server = RpcServer::make();
    server->setRootObject(sp<SomeBinder>::make());
    server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    CHECK(server->setupUnixDomainServer(kSock.c_str()));

    // FIXME: there is a leak!
    static size_t i = 0;
    i++;
    if (i % 100 == 0) system((std::string("pmap ") + std::to_string(getpid())).c_str());

    static constexpr size_t kMemLimit = 1llu * 1024 * 1024 * 1024;
    size_t hardLimit = getHardMemoryLimit();
    setMemoryLimit(std::min(kMemLimit, hardLimit), hardLimit);

    std::thread serverThread([=] { server->join(); });

    sockaddr_un addr{
            .sun_family = AF_UNIX,
    };
    CHECK_LT(kSock.size(), sizeof(addr.sun_path));
    memcpy(&addr.sun_path, kSock.c_str(), kSock.size());

    // FIXME: fuzz multiple connections at the same time

    base::unique_fd clientFd(TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    CHECK_NE(clientFd.get(), -1);
    CHECK_EQ(0,
             TEMP_FAILURE_RETRY(
                     connect(clientFd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr))))
            << strerror(errno);

#if 1
    // make fuzzer more productive by forcing it to create a new session
    int32_t id = -1;
    CHECK(base::WriteFully(clientFd, &id, sizeof(id)));
#endif

    // the fuzzer!
    CHECK(base::WriteFully(clientFd, data, size));

    clientFd.reset();

    // FIXME: way to force it to shutdown (no break)
    serverThread.join();

    // FIXME: better way to wait for it to shutdown
    while (!server->listSessions().empty()) {
        usleep(1);
    }

    setMemoryLimit(hardLimit, hardLimit);

    return 0;
}

} // namespace android
