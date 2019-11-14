/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <adbwifi/fdevent/fdevent.h>
#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

namespace adbwifi {
namespace fdevent {

bool ReadFdExactly(android::base::borrowed_fd fd, void* buf, size_t len) {
    char* p = reinterpret_cast<char*>(buf);

    LOG(INFO) << android::base::StringPrintf("readx: fd=%d wanted=%zu", fd.get(), len);
    while (len > 0) {
        int r = sysdeps::adb_read(fd, p, len);
        if (r > 0) {
            len -= r;
            p += r;
        } else if (r == -1) {
            LOG(INFO) << android::base::StringPrintf("readx: fd=%d error %d: %s", fd.get(), errno, strerror(errno));
            return false;
        } else {
            LOG(INFO) << android::base::StringPrintf("readx: fd=%d disconnected", fd.get());
            errno = 0;
            return false;
        }
    }

    return true;
}

bool WriteFdExactly(android::base::borrowed_fd fd, const void* buf, size_t len) {
    const char* p = reinterpret_cast<const char*>(buf);
    int r;

    LOG(INFO) << android::base::StringPrintf("writex: fd=%d wanted=%zu", fd.get(), len);
    while (len > 0) {
        r = sysdeps::adb_write(fd, p, len);
        if (r == -1) {
            LOG(INFO) << android::base::StringPrintf("writex: fd=%d error %d: %s", fd.get(), errno, strerror(errno));
            if (errno == EAGAIN) {
                std::this_thread::yield();
                continue;
            } else if (errno == EPIPE) {
                LOG(INFO) << android::base::StringPrintf("writex: fd=%d disconnected", fd.get());
                errno = 0;
                return false;
            } else {
                return false;
            }
        } else {
            len -= r;
            p += r;
        }
    }
    return true;
}

bool WriteFdExactly(android::base::borrowed_fd fd, const char* str) {
    return WriteFdExactly(fd, str, strlen(str));
}

bool WriteFdExactly(android::base::borrowed_fd fd, const std::string& str) {
    return WriteFdExactly(fd, str.c_str(), str.size());
}

static void WaitForFdeventLoop() {
    // Sleep for a bit to make sure that network events have propagated.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // fdevent_run_on_main_thread has a guaranteed ordering, and is guaranteed to happen after
    // socket events, so as soon as our function is called, we know that we've processed all
    // previous events.
    std::mutex mutex;
    std::condition_variable cv;
    std::unique_lock<std::mutex> lock(mutex);
    fdevent_run_on_main_thread([&]() {
        mutex.lock();
        mutex.unlock();
        cv.notify_one();
    });
    cv.wait(lock);
}

class DummySocket {
public:
    explicit DummySocket(android::base::unique_fd ufd) {
        int fd = ufd.release();
        LOG(INFO) << "creating DummySocket fd=" << fd;
        fde_ = fdevent_create(fd, DummySocket::onFdEvent, this);
    }

    void ready() {
        // The far side is ready for data, pay attention to readable event.
        fdevent_add(fde_, FDE_READ);
    }

    static void onFdEvent(int fd, unsigned ev, void* s) {
        LOG(INFO) << "Got dummy fd event";
        auto dummy_sock = reinterpret_cast<DummySocket*>(s);
        if ((FDE_READ & ev) == 0 || fd != dummy_sock->fde_->fd.get()) {
            return;
        }
        uint8_t c = 0xff;
        if (!ReadFdExactly(fd, &c, 1)) {
            ASSERT_EQ(0, c);
            // This just means we are about to terminate.
            LOG(INFO) << "Notified of shutdown.";
        }
    }

private:
    fdevent* fde_ = nullptr;
}; // DummySocket

class FdeventTest : public ::testing::Test {
  protected:
    android::base::unique_fd dummy_;
    std::unique_ptr<DummySocket> dummy_socket_;

    ~FdeventTest() {
        if (thread_.joinable()) {
            TerminateThread();
        }
    }

    static void SetUpTestCase() {
#if !defined(_WIN32)
        ASSERT_NE(SIG_ERR, signal(SIGPIPE, SIG_IGN));
#endif
    }

    void SetUp() override {
        fdevent_reset();
        ASSERT_EQ(0u, fdevent_installed_count());
    }

    // Register a dummy socket used to wake up the fde_vent loop to tell it to die.
    void PrepareThread() {
        int dummy_fds[2];
        if (sysdeps::adb_socketpair(dummy_fds) != 0) {
            FAIL() << "failed to create socketpair: " << strerror(errno);
        }

        LOG(INFO) << "created dummyfd=" << dummy_fds[0] << " DummySocketfd=" << dummy_fds[1];
        dummy_socket_.reset(new DummySocket(android::base::unique_fd(dummy_fds[1])));
        if (!dummy_socket_) {
            FAIL() << "failed to create local socket: " << strerror(errno);
        }
        dummy_socket_->ready();
        dummy_.reset(dummy_fds[0]);

        thread_ = std::thread([]() { fdevent_loop(); });
        WaitForFdeventLoop();
    }

    size_t GetAdditionalLocalSocketCount() {
        // dummy socket installed in PrepareThread()
        return 1;
    }

    void TerminateThread() {
        fdevent_terminate_loop();
        ASSERT_TRUE(WriteFdExactly(dummy_, "", 1));
        thread_.join();
        dummy_.reset();
    }

    std::thread thread_;
};

} //  namespace fdevent
} //  namespace adbwifi
