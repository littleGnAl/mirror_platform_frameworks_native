/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "PipeRelay.h"

#include <thread>

#include <android-base/logging.h>

#include <chrono>
#include <mutex>


namespace android {
namespace lshal {

constexpr std::chrono::milliseconds READ_TIMEOUT{100};

struct PipeRelay::RelayThread {
    explicit RelayThread(int fd, std::ostream &os);

    bool threadLoop();
    int run(const char* name);

    template<typename R, typename P>
    void waitUntilFinished(std::chrono::duration<R, P> timeout);

private:
    int mFd;
    std::ostream &mOutStream;
    std::unique_ptr<std::thread> mThread;

    std::mutex mMutex;
    std::condition_variable mCv;
    bool mFinished;

    void notifyFinished();

    DISALLOW_COPY_AND_ASSIGN(RelayThread);
};

////////////////////////////////////////////////////////////////////////////////

PipeRelay::RelayThread::RelayThread(int fd, std::ostream &os)
    : mFd(fd),
      mOutStream(os),
      mFinished(false) {

}

int PipeRelay::RelayThread::RelayThread::run(const char* name) {
    mThread = std::make_unique<std::thread>([this] {
        while (threadLoop());
    });
    return pthread_setname_np(mThread->native_handle(), name);
}

bool PipeRelay::RelayThread::threadLoop() {
    char buffer[1024];
    ssize_t n = read(mFd, buffer, sizeof(buffer));

    if (n <= 0) {
        notifyFinished();
        return false;
    }

    mOutStream.write(buffer, n);

    return true;
}

template<typename R, typename P>
void PipeRelay::RelayThread::waitUntilFinished(std::chrono::duration<R, P> timeout) {
    std::unique_lock<std::mutex> lock(mMutex);
    mCv.wait_for(lock, timeout, [this] { return mFinished; });

    if (!mFinished) {
        LOG(WARNING) << "debug: timeout has reached. Output may be truncated.";
        pthread_kill(mThread->native_handle(), SIGINT);
    }

    lock.unlock();

    mThread->join();
    mThread.reset();
}

void PipeRelay::RelayThread::notifyFinished() {
    std::unique_lock<std::mutex> lock(mMutex);
    mFinished = true;
    lock.unlock();
    mCv.notify_all();
}

////////////////////////////////////////////////////////////////////////////////

PipeRelay::PipeRelay(std::ostream &os)
    : mInitCheck(NO_INIT) {
    int res = pipe(mFds);

    if (res < 0) {
        mInitCheck = -errno;
        return;
    }

    mThread = std::make_unique<RelayThread>(mFds[0], os);
    mInitCheck = mThread->run("RelayThread");
}

void PipeRelay::CloseFd(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

PipeRelay::~PipeRelay() {
    CloseFd(&mFds[1]);

    if (mThread != nullptr) {
        mThread->waitUntilFinished(READ_TIMEOUT);
        mThread.reset();
    }

    CloseFd(&mFds[0]);

}

status_t PipeRelay::initCheck() const {
    return mInitCheck;
}

int PipeRelay::fd() const {
    return mFds[1];
}

}  // namespace lshal
}  // namespace android
