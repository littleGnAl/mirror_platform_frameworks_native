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

#include "include/adbd_wifi.h"

#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/uio.h>

#include <chrono>
#include <deque>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/strings.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#define DEBUGON 1

using android::base::unique_fd;

struct AdbdWifiPacketConnected {
    std::string guid;
};

struct AdbdWifiPacketDisconnected {
    std::string guid;
};

using AdbdWifiPacket = std::variant<AdbdWifiPacketConnected,
                                    AdbdWifiPacketDisconnected>;

struct AdbdWifiContext {
public:
    explicit AdbdWifiContext(AdbdWifiCallbacksV1* callbacks) : next_id_(0), callbacks_(*callbacks) {
        epoll_fd_.reset(epoll_create1(EPOLL_CLOEXEC));
        if (epoll_fd_ == -1) {
            PLOG(FATAL) << "failed to create epoll fd";
        }

        event_fd_.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
        if (event_fd_ == -1) {
            PLOG(FATAL) << "failed to create eventfd";
        }

        sock_fd_.reset(android_get_control_socket("adbdwifi"));
        if (sock_fd_ == -1) {
            PLOG(ERROR) << "failed to get adbdwifi socket";
        } else {
            if (fcntl(sock_fd_.get(), F_SETFD, FD_CLOEXEC) != 0) {
                PLOG(FATAL) << "failed to make adbdwifi socket nonblocking";
            }

            if (listen(sock_fd_.get(), 4) != 0) {
                PLOG(FATAL) << "failed to listen on adbdwifi socket";
            }
            PLOG(WARNING) << "AdbdWifiContext listening to adbdwifi socket";
        }
    }

    AdbdWifiContext(const AdbdWifiContext& copy) = delete;
    AdbdWifiContext(AdbdWifiContext&& move) = delete;
    AdbdWifiContext& operator=(const AdbdWifiContext& copy) = delete;
    AdbdWifiContext& operator=(AdbdWifiContext&& move) = delete;

    void Run() EXCLUDES(mutex_) {
        if (sock_fd_ == -1) {
            LOG(ERROR) << "adbdwifi socket unavailable, disabling user prompts";
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
            PLOG(WARNING) << "Waiting for events (epoll_wait)";
            int rc = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd_.get(), events, 3, -1));
            if (rc == -1) {
                PLOG(FATAL) << "epoll_wait failed";
            } else if (rc == 0) {
                LOG(FATAL) << "epoll_wait returned 0";
            }
            PLOG(WARNING) << "returned from epoll_wait(rc=" << rc << ")";

            bool restart = false;
            for (int i = 0; i < rc; ++i) {
                if (restart) {
                    PLOG(WARNING) << "Got new framework_fd. Need to restart";
                    break;
                }

                struct epoll_event& event = events[i];
                PLOG(WARNING) << "Got packet [" << event.data.u64 << "]";
                switch (event.data.u64) {
                    case kEpollConstSocket: {
                        PLOG(WARNING) << "Got new socket request. Trying to accept the new framework_fd";
                        unique_fd new_framework_fd(accept4(sock_fd_.get(), nullptr, nullptr,
                                                           SOCK_CLOEXEC | SOCK_NONBLOCK));
                        PLOG(WARNING) << "accepted the socket connection";
                        if (new_framework_fd == -1) {
                            PLOG(FATAL) << "failed to accept framework fd";
                        }

                        PLOG(WARNING) << __func__ << ": Waiting for mutex to update the framework_fd";
                        std::lock_guard<std::mutex> lock(mutex_);
                        ReplaceFrameworkFd(std::move(new_framework_fd));

                        // Stop iterating over events: one of the later ones might be the old
                        // framework fd.
                        restart = true;
                        break;
                    }

                    case kEpollConstEventFd: {
                        // We were woken up to write something.
                        LOG(INFO) << "Got woken up. Let's write something!";
                        // Need to read() or epoll_wait will keep waking up on
                        // this event.
                        uint64_t buf;
                        int rc = TEMP_FAILURE_RETRY(read(event_fd_.get(), &buf, sizeof(buf)));
                        if (rc == -1) {
                            LOG(FATAL) << "failed to read from framework fd";
                        } else if (rc == 0) {
                            LOG(INFO) << "hit unexpected EOF on framework fd";
                        } else {
                            LOG(INFO) << "Lock to update framework";
                            std::lock_guard<std::mutex> lock(mutex_);
                            LOG(INFO) << "Unlock to update framework";
                            UpdateFrameworkWritable();
                        }
                        break;
                    }

                    case kEpollConstFramework: {
                        char buf[4096];
                        if (event.events & EPOLLOUT) {
                            PLOG(WARNING) << "stuff in the output_queue. Writing it.";
                            std::lock_guard<std::mutex> lock(mutex_);
                            while (SendPacket()) {
                                continue;
                            }
                            UpdateFrameworkWritable();
                        }
                        if (event.events & EPOLLIN) {
                            int rc = TEMP_FAILURE_RETRY(read(framework_fd_.get(), buf, sizeof(buf)));
                            if (rc == -1) {
                                LOG(FATAL) << "failed to read from framework fd";
                            } else if (rc == 0) {
                                LOG(INFO) << "hit EOF on framework fd";
                                std::lock_guard<std::mutex> lock(mutex_);
                                ReplaceFrameworkFd(unique_fd());
                            } else {
                                std::lock_guard<std::mutex> lock(mutex_);
                                HandlePacket(std::string_view(buf, rc));
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    uint64_t NotifyConnected(std::string_view guid) EXCLUDES(mutex_) {
        uint64_t id = NextId();
        std::lock_guard<std::mutex> lock(mutex_);
        guids_.emplace(id, guid);
        output_queue_.emplace_back(
                AdbdWifiPacketConnected{.guid = std::string(guid)});
        LOG(INFO) << "Got adbwifi connect guid=" << guid << " id=" << id;
        Interrupt();
        return id;
    }

    void NotifyDisconnected(uint64_t id) EXCLUDES(mutex_) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Just ignore if the framework is disconnected. This means that
        // wireless debugging is turned off.
        if (framework_fd_ != -1) {
            return;
        }
        auto it = guids_.find(id);
        if (it == guids_.end()) {
            LOG(DEBUG) << "couldn't find public key to notify disconnection, skipping";
            return;
        }
        LOG(INFO) << "Got adbwifi disconnect guid=" << it->second << " id=" << id;
        output_queue_.emplace_back(AdbdWifiPacketDisconnected{.guid = std::move(it->second)});
        Interrupt();
        guids_.erase(it);
    }

private:
    static constexpr const char* key_paths[] = {"/adb_wifi_keys", "/data/misc/adb/adb_wifi_keys"};
    static constexpr uint64_t kEpollConstSocket = 0;
    static constexpr uint64_t kEpollConstEventFd = 1;
    static constexpr uint64_t kEpollConstFramework = 2;

    uint64_t NextId() { return next_id_++; }

    void UpdateFrameworkWritable() REQUIRES(mutex_) {
        // This might result in redundant calls to EPOLL_CTL_MOD if, for example, we get notified
        // at the same time as a framework connection, but that's unlikely and this doesn't need to
        // be fast anyway.
        if (framework_fd_ != -1) {
            struct epoll_event event;
            event.events = EPOLLIN;
            if (!output_queue_.empty()) {
                event.events |= EPOLLOUT;
            }
            event.data.u64 = kEpollConstFramework;
            CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_MOD, framework_fd_.get(), &event));
        }
    }

    void ReplaceFrameworkFd(unique_fd new_fd) REQUIRES(mutex_) {
        // If we already had a framework fd, clean up after ourselves.
        PLOG(WARNING) << __func__ << ": framework_fd=" << framework_fd_.get() << ", new_fd=" << new_fd.get();
        if (framework_fd_ != -1) {
            PLOG(WARNING) << __func__ << ": Cleaning up old fd events";
            CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, framework_fd_.get(), nullptr));
            framework_fd_.reset();
            output_queue_.clear();
            guids_.clear();
            callbacks_.on_framework_disconnected();
        }

        if (new_fd != -1) {
            PLOG(WARNING) << __func__ << ": Migrating to new framework_fd";
            struct epoll_event event;
            event.events = EPOLLIN;
            if (!output_queue_.empty()) {
                event.events |= EPOLLOUT;
            }
            event.data.u64 = kEpollConstFramework;
            CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, new_fd.get(), &event));
            framework_fd_ = std::move(new_fd);
            callbacks_.on_framework_connected();
        }
    }


    // system_server request handlers
    static void requestDisconnectDevice(std::string_view buf, void* opaque) {
        auto* p = reinterpret_cast<AdbdWifiContext*>(opaque);
        p->callbacks_.on_device_unpaired(buf.data() + 2, buf.length() - 2);
    }

    static void requestDisableAdbdWifi(std::string_view buf, void* opaque) {
        UNUSED(buf);
        auto* p = reinterpret_cast<AdbdWifiContext*>(opaque);
        // It seems we sometimes don't get the disconnect event from adbwifi
        // socket when the framework closes the connection. So system_server
        // will also explicitly tell us it is going to close it here.
        p->callbacks_.on_framework_disconnected();
    }

    using QueryCallback = std::function<void(std::string_view, void*)>;
    struct QueryHandler {
        const char* code;
        QueryCallback cb;
    };
    static const QueryHandler kQueries[];
    static const size_t kNumQueries;

    void HandlePacket(std::string_view packet) REQUIRES(mutex_) {
        LOG(INFO) << "received packet: [" << packet << "]";

        if (packet.length() < 2) {
            LOG(ERROR) << "received packet of invalid length";
            ReplaceFrameworkFd(unique_fd());
        }

        bool handledPacket = false;
        for (size_t i = 0; i < kNumQueries; ++i) {
            if (kQueries[i].code[0] == packet[0] &&
                kQueries[i].code[1] == packet[1]) {
                kQueries[i].cb(packet, this);
                handledPacket = true;
                break;
            }
        }
        if (!handledPacket) {
            LOG(ERROR) << "unhandled packet: [" << packet << "]";
            ReplaceFrameworkFd(unique_fd());
        }
    }

private:
    bool SendPacket() REQUIRES(mutex_) {
        PLOG(WARNING) << __func__ << " output_queue_.size=" << output_queue_.size();
        if (output_queue_.empty()) {
            return false;
        }

        CHECK_NE(-1, framework_fd_.get());

        auto& packet = output_queue_.front();
        struct iovec iovs[2];
        if (auto* p = std::get_if<AdbdWifiPacketConnected>(&packet)) {
            iovs[0].iov_base = const_cast<char*>("CN");
            iovs[0].iov_len = 2;
            iovs[1].iov_base = p->guid.data();
            iovs[1].iov_len = p->guid.size();
        } else if (auto* p = std::get_if<AdbdWifiPacketDisconnected>(&packet)) {
            iovs[0].iov_base = const_cast<char*>("DC");
            iovs[0].iov_len = 2;
            iovs[1].iov_base = p->guid.data();
            iovs[1].iov_len = p->guid.size();
        } else {
            LOG(FATAL) << "unhandled packet type?";
        }

        output_queue_.pop_front();

        ssize_t rc = writev(framework_fd_.get(), iovs, 2);
        if (rc == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            PLOG(ERROR) << "failed to write to framework fd";
            ReplaceFrameworkFd(unique_fd());
            return false;
        }

        PLOG(WARNING) << "Successfully sent AdbdWifiPacket";
        return true;
    }

    // Interrupt the worker thread to do some work.
    void Interrupt() {
        PLOG(WARNING) << __func__;
        uint64_t value = 1;
        ssize_t rc = write(event_fd_.get(), &value, sizeof(value));
        if (rc == -1) {
            PLOG(FATAL) << "write to eventfd failed";
        } else if (rc != sizeof(value)) {
            LOG(FATAL) << "write to eventfd returned short (" << rc << ")";
        }
    }

    unique_fd epoll_fd_;
    unique_fd event_fd_;
    unique_fd sock_fd_;
    unique_fd framework_fd_;

    std::atomic<uint64_t> next_id_;
    AdbdWifiCallbacksV1 callbacks_;

    std::mutex mutex_;
    std::unordered_map<uint64_t, std::string> guids_ GUARDED_BY(mutex_);

    // A queue to handle backpressure from the socket (output_queue_)
    std::deque<AdbdWifiPacket> output_queue_ GUARDED_BY(mutex_);

    std::vector<uint8_t> mOurKey;
};  // struct AdbdWifiContext

// This is a list of commands that system_server could send to us.
// static
const AdbdWifiContext::QueryHandler AdbdWifiContext::kQueries[] = {
        {"DD", &AdbdWifiContext::requestDisconnectDevice},
        {"DA", &AdbdWifiContext::requestDisableAdbdWifi},
};

// static
const size_t AdbdWifiContext::kNumQueries =
        sizeof(AdbdWifiContext::kQueries) / sizeof(AdbdWifiContext::kQueries[0]);

/******************************* Exposed functions **************************************/
AdbdWifiContext* adbd_wifi_new(AdbdWifiCallbacks* callbacks) {
    if (callbacks->version != 1) {
      LOG(ERROR) << "received unknown AdbdWifiCallbacks version " << callbacks->version;
      return nullptr;
    }

    return new AdbdWifiContext(&callbacks->callbacks.v1);
}

void adbd_wifi_delete(AdbdWifiContext* ctx) {
    delete ctx;
}

void adbd_wifi_run(AdbdWifiContext* ctx) {
    return ctx->Run();
}

uint64_t adbd_wifi_notify_connected(AdbdWifiContext* ctx, const char* guid, size_t len) {
    return ctx->NotifyConnected(std::string_view(guid, len));
}

void adbd_wifi_notify_disconnected(AdbdWifiContext* ctx, uint64_t id) {
    return ctx->NotifyDisconnected(id);
}

bool adbd_wifi_supports_feature(AdbdWifiFeature) {
    return false;
}
