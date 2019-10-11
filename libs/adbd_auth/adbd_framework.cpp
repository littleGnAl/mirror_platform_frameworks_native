/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define ANDROID_BASE_UNIQUE_FD_DISABLE_IMPLICIT_CONVERSION

#include "include/adbd_framework.h"

#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/uio.h>

#include <chrono>
#include <deque>
#include <string>
#include <string_view>
#include <tuple>
//#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

using android::base::unique_fd;

AdbdFramework::AdbdFramework(const char* sock_name) {
    epoll_fd_.reset(epoll_create1(EPOLL_CLOEXEC));
    if (epoll_fd_ == -1) {
        PLOG(FATAL) << "failed to create epoll fd";
    }

    event_fd_.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (event_fd_ == -1) {
        PLOG(FATAL) << "failed to create eventfd";
    }

    sock_fd_.reset(android_get_control_socket(sock_name));
    if (sock_fd_ == -1) {
        PLOG(ERROR) << "failed to get " << sock_name << " socket";
    } else {
        if (fcntl(sock_fd_.get(), F_SETFD, FD_CLOEXEC) != 0) {
            PLOG(FATAL) << "failed to make adbd authentication socket cloexec";
        }

        if (fcntl(sock_fd_.get(), F_SETFL, O_NONBLOCK) != 0) {
            PLOG(FATAL) << "failed to make adbd authentication socket nonblocking";
        }

        if (listen(sock_fd_.get(), 4) != 0) {
            PLOG(FATAL) << "failed to listen on adbd authentication socket";
        }
    }
}

void AdbdFramework::UpdateFrameworkWritable() {
    // This might result in redundant calls to EPOLL_CTL_MOD if, for example, we get notified
    // at the same time as a framework connection, but that's unlikely and this doesn't need to
    // be fast anyway.
    if (framework_fd_ != -1) {
        struct epoll_event event;
        event.events = EPOLLIN;
        if (HasPacketForWriting()) {
            LOG(INFO) << "marking framework writable";
            event.events |= EPOLLOUT;
        }
        event.data.u64 = kEpollConstFramework;
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_MOD, framework_fd_.get(), &event));
    }
}

void AdbdFramework::ReplaceFrameworkFd(unique_fd new_fd) {
    LOG(INFO) << "received new framework fd " << new_fd.get()
              << " (current = " << framework_fd_.get() << ")";

    // If we already had a framework fd, clean up after ourselves.
    if (framework_fd_ != -1) {
        FrameworkDisconnected();
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, framework_fd_.get(), nullptr));
        framework_fd_.reset();
    }

    if (new_fd != -1) {
        FrameworkConnected();
        struct epoll_event event;
        event.events = EPOLLIN;
        if (HasPacketForWriting()) {
            LOG(INFO) << "marking framework writable";
            event.events |= EPOLLOUT;
        }
        event.data.u64 = kEpollConstFramework;
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, new_fd.get(), &event));
        framework_fd_ = std::move(new_fd);
    }
}

bool AdbdFramework::SendPacket() {
    CHECK_NE(-1, framework_fd_.get());

    auto pkt = FetchPacket();
    if (!pkt) {
        // No data
        return false;
    }
    auto [code, data] = *pkt;

    struct iovec iovs[2];
    iovs[0].iov_base = code.data();
    iovs[0].iov_len = code.size();
    iovs[1].iov_base = data.data();
    iovs[1].iov_len = data.size();

    ssize_t rc = writev(framework_fd_.get(), iovs, 2);
    if (rc == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
        PLOG(ERROR) << "failed to write to framework fd";
        ReplaceFrameworkFd(unique_fd());
        return false;
    }

    return true;
}

void AdbdFramework::Run() {
    if (sock_fd_ == -1) {
        LOG(ERROR) << "adbd authentication socket unavailable, disabling user prompts";
    } else {
        struct epoll_event event;
        event.events = EPOLLIN;
        event.data.u64 = kEpollConstSocket;
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, sock_fd_.get(), &event));
    }

    {
        struct epoll_event event;
        event.events = EPOLLIN;
        event.data.u64 = kEpollConstEventFd;
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, event_fd_.get(), &event));
    }

    while (true) {
        struct epoll_event events[3];
        int rc = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd_.get(), events, 3, -1));
        if (rc == -1) {
            PLOG(FATAL) << "epoll_wait failed";
        } else if (rc == 0) {
            LOG(FATAL) << "epoll_wait returned 0";
        }

        bool restart = false;
        for (int i = 0; i < rc; ++i) {
            if (restart) {
                break;
            }

            struct epoll_event& event = events[i];
            switch (event.data.u64) {
                case kEpollConstSocket: {
                    unique_fd new_framework_fd(accept4(sock_fd_.get(), nullptr, nullptr,
                                                       SOCK_CLOEXEC | SOCK_NONBLOCK));
                    if (new_framework_fd == -1) {
                        PLOG(FATAL) << "failed to accept framework fd";
                    }

                    LOG(INFO) << "adbd_auth: received a new framework connection";
                    ReplaceFrameworkFd(std::move(new_framework_fd));

                    // Stop iterating over events: one of the later ones might be the old
                    // framework fd.
                    restart = false;
                    break;
                }

                case kEpollConstEventFd: {
                    // We were woken up to write something.
                    uint64_t dummy;
                    int rc = TEMP_FAILURE_RETRY(read(event_fd_.get(), &dummy, sizeof(dummy)));
                    if (rc != 8) {
                        PLOG(FATAL) << "failed to read from eventfd (rc = " << rc << ")";
                    }

                    UpdateFrameworkWritable();
                    break;
                }

                case kEpollConstFramework: {
                    char buf[4096];
                    if (event.events & EPOLLIN) {
                        int rc = TEMP_FAILURE_RETRY(read(framework_fd_.get(), buf, sizeof(buf)));
                        if (rc == -1) {
                            LOG(FATAL) << "failed to read from framework fd";
                        } else if (rc == 0) {
                            LOG(INFO) << "hit EOF on framework fd";
                            ReplaceFrameworkFd(unique_fd());
                        } else if (!HandlePacket(std::string_view(buf, rc))) {
                            LOG(WARNING) << "Unhandled packet from framework (size=" << rc << ").";
                            ReplaceFrameworkFd(unique_fd());
                        }
                    }

                    if (event.events & EPOLLOUT) {
                        while (SendPacket()) {
                            continue;
                        }
                        UpdateFrameworkWritable();
                    }

                    break;
                }
            }
        }
    }
}

// Interrupt the worker thread to do some work.
void AdbdFramework::Interrupt() {
    uint64_t value = 1;
    ssize_t rc = write(event_fd_.get(), &value, sizeof(value));
    if (rc == -1) {
        PLOG(FATAL) << "write to eventfd failed";
    } else if (rc != sizeof(value)) {
        LOG(FATAL) << "write to eventfd returned short (" << rc << ")";
    }
}
