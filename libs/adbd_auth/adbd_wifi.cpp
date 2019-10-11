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
#include <string>
#include <string_view>
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

struct AdbdWifiPacketAuthenticated {
    std::string public_key;
};

struct AdbdWifiPacketDisconnected {
    std::string public_key;
};

struct AdbdWifiPacketRequestAuthorization {
    std::string public_key;
};

struct AdbdWifiPacketPairingCode {
    std::string pairing_code;
    int device_id;
    std::string&& toString() const {
        std::string res = pairing_code + '\n' + std::to_string(device_id);
        return std::move(res);
    }
};  // AdbdWifiPacketPairingCode

using AdbdWifiPacket = std::variant<AdbdWifiPacketAuthenticated,
                                    AdbdWifiPacketDisconnected,
                                    AdbdWifiPacketRequestAuthorization,
                                    AdbdWifiPacketPairingCode>;

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

    void Run() {
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
                PLOG(WARNING) << "Got packet [" << event.data.u64 << "]";
                switch (event.data.u64) {
                    case kEpollConstSocket: {
                        unique_fd new_framework_fd(accept4(sock_fd_.get(), nullptr, nullptr,
                                                           SOCK_CLOEXEC | SOCK_NONBLOCK));
                        if (new_framework_fd == -1) {
                            PLOG(FATAL) << "failed to accept framework fd";
                        }

                        std::lock_guard<std::mutex> lock(mutex_);
                        ReplaceFrameworkFd(std::move(new_framework_fd));

                        // Stop iterating over events: one of the later ones might be the old
                        // framework fd.
                        restart = false;
                        break;
                    }

                    case kEpollConstEventFd: {
                        // We were woken up to write something.
                        std::lock_guard<std::mutex> lock(mutex_);
                        UpdateFrameworkWritable();
                        break;
                    }

                    case kEpollConstFramework: {
                        char buf[4096];
                        if (event.events & EPOLLIN) {
                            rc = TEMP_FAILURE_RETRY(read(framework_fd_.get(), buf, sizeof(buf)));
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

                        if (event.events & EPOLLOUT) {
                            std::lock_guard<std::mutex> lock(mutex_);
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

    void IteratePublicKeys(bool (*callback)(const char*, size_t, void*), void* arg) {
        for (const auto& path : key_paths) {
            if (access(path, R_OK) == 0) {
                LOG(INFO) << "Loading keys from " << path;
                std::string content;
                if (!android::base::ReadFileToString(path, &content)) {
                    PLOG(ERROR) << "Couldn't read " << path;
                    continue;
                }
                for (const auto& line : android::base::Split(content, "\n")) {
                    if (!callback(line.data(), line.size(), arg)) {
                        return;
                    }
                }
            }
        }
    }

    uint64_t NotifyAuthenticated(std::string_view public_key) EXCLUDES(mutex_) {
        uint64_t id = NextId();
        std::lock_guard<std::mutex> lock(mutex_);
        keys_.emplace(id, public_key);
        output_queue_.emplace_back(
                AdbdWifiPacketDisconnected{.public_key = std::string(public_key)});
        return id;
    }

    void NotifyDisconnected(uint64_t id) EXCLUDES(mutex_) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(id);
        if (it == keys_.end()) {
            LOG(DEBUG) << "couldn't find public key to notify disconnection, skipping";
            return;
        }
        output_queue_.emplace_back(AdbdWifiPacketDisconnected{.public_key = std::move(it->second)});
        keys_.erase(it);
    }

private:
    static constexpr const char* key_paths[] = {"/adb_wifi_keys", "/data/misc/adb/adb_wifi_keys"};
    static constexpr uint64_t kEpollConstSocket = 0;
    static constexpr uint64_t kEpollConstEventFd = 1;
    static constexpr uint64_t kEpollConstFramework = 2;

    uint64_t NextId() { return next_id_++; }

    void DispatchPendingPrompt() REQUIRES(mutex_) {
        if (dispatched_prompt_) {
            return;
        }

        if (pending_prompts_.empty()) {
            return;
        }

        auto [id, public_key, arg] = std::move(pending_prompts_.front());
        pending_prompts_.pop_front();

        this->output_queue_.emplace_back(
                AdbdWifiPacketRequestAuthorization{.public_key = public_key});

        Interrupt();
        dispatched_prompt_ = std::make_tuple(id, public_key, arg);
    }

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
        if (framework_fd_ != -1) {
            dispatched_prompt_.reset();
            CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, framework_fd_.get(), nullptr));
            framework_fd_.reset();
        }

        if (new_fd != -1) {
            struct epoll_event event;
            event.events = EPOLLIN;
            if (!output_queue_.empty()) {
                event.events |= EPOLLOUT;
            }
            event.data.u64 = kEpollConstFramework;
            CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, new_fd.get(), &event));
            framework_fd_ = std::move(new_fd);
        }
    }


    // Query codes and handlers from WirelessDebuggingManager to adbd
    static void queryGetDeviceName(std::string_view buf, void* opaque) {
        UNUSED(buf);
        UNUSED(opaque);
        PLOG(WARNING) << "NOT IMPLEMENTED";
    }

    static void querySetDeviceName(std::string_view buf, void* opaque) {
        UNUSED(buf);
        UNUSED(opaque);
        PLOG(WARNING) << "NOT IMPLEMENTED";
    }

    static void queryPairedDevicesList(std::string_view buf, void* opaque) {
        UNUSED(buf);
        UNUSED(opaque);
        PLOG(WARNING) << "NOT IMPLEMENTED";
        // TODO: system server should have the keystore, so no need to have this
        // here.
    }

    static void queryPairingDevicesList(std::string_view buf, void* opaque) {
        UNUSED(buf);
        UNUSED(opaque);
        PLOG(WARNING) << "NOT IMPLEMENTED";
        // TODO: might not need this. Only one device can pair at a time, so a
        // list doesn't make any sense.
    }

    static void queryPairDevice(std::string_view buf, void* opaque) {
        UNUSED(buf);
        UNUSED(opaque);
        PLOG(WARNING) << "NOT IMPLEMENTED";
    }

    static void queryUnpairDevice(std::string_view buf, void* opaque) {
        UNUSED(buf);
        UNUSED(opaque);
        PLOG(WARNING) << "NOT IMPLEMENTED";
    }

    static void queryCancelPairing(std::string_view buf, void* opaque) {
        UNUSED(buf);

        auto* p = reinterpret_cast<AdbdWifiContext*>(opaque);
        PLOG(DEBUG) << "Cancel pairing";
        p->callbacks_.set_discovery_enabled(false);
    }

    static void queryEnableDiscovery(std::string_view buf, void* opaque) {
        UNUSED(buf);

        auto* p = reinterpret_cast<AdbdWifiContext*>(opaque);
        PLOG(DEBUG) << "Discovery enabled";
        p->callbacks_.set_discovery_enabled(true);
    }

    static void queryDisableDiscovery(std::string_view buf, void* opaque) {
        UNUSED(buf);

        auto* p = reinterpret_cast<AdbdWifiContext*>(opaque);
        PLOG(DEBUG) << "Discovery disabled";
        p->callbacks_.set_discovery_enabled(false);
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

    // Response codes from adbd to WirelessDebuggingManager
    static constexpr const char kResponseDeviceName[] = "DN";
    static constexpr const char kResponsePairedDevicesList[] = "PD";
    static constexpr const char kResponsePairingDevicesList[] = "PI";
    static constexpr const char kResponsePairingCode[] = "CD";
    // Response code status for the above
    static constexpr const char kStatusOk[] = "OK";
    static constexpr const char kStatusFailed[] = "FA";
    static constexpr const char kStatusCancel[] = "CA";

public:
    // Response handlers
    void responsePairingCode(const std::string& pairing_code,
                             int device_id,
                             void (*callback)(uint64_t device_id, bool isCorrect)) {
        UNUSED(callback);
        this->output_queue_.emplace_back(
                AdbdWifiPacketPairingCode{
                        .pairing_code = pairing_code,
                        .device_id = device_id});
        Interrupt();
        // TODO: call |callback| once we are notified from system_server.
    }

    void responsePairingResult(const std::string& status, int deviceId) {
        UNUSED(status);
        UNUSED(deviceId);
        PLOG(WARNING) << "NOT IMPLEMENTED";
    }

    void responseUnpairResult(const std::string& status, int deviceId) {
        UNUSED(status);
        UNUSED(deviceId);
        PLOG(WARNING) << "NOT IMPLEMENTED";
    }

private:
    bool SendPacket() REQUIRES(mutex_) {
        if (output_queue_.empty()) {
            return false;
        }

        CHECK_NE(-1, framework_fd_.get());

        auto& packet = output_queue_.front();
        struct iovec iovs[2];
        if (auto* p = std::get_if<AdbdWifiPacketAuthenticated>(&packet)) {
            iovs[0].iov_base = const_cast<char*>("CK");
            iovs[0].iov_len = 2;
            iovs[1].iov_base = p->public_key.data();
            iovs[1].iov_len = p->public_key.size();
        } else if (auto* p = std::get_if<AdbdWifiPacketDisconnected>(&packet)) {
            iovs[0].iov_base = const_cast<char*>("DC");
            iovs[0].iov_len = 2;
            iovs[1].iov_base = p->public_key.data();
            iovs[1].iov_len = p->public_key.size();
        } else if (auto* p = std::get_if<AdbdWifiPacketRequestAuthorization>(&packet)) {
            iovs[0].iov_base = const_cast<char*>("PK");
            iovs[0].iov_len = 2;
            iovs[1].iov_base = p->public_key.data();
            iovs[1].iov_len = p->public_key.size();
        } else if (auto* p = std::get_if<AdbdWifiPacketPairingCode>(&packet)) {
            iovs[0].iov_base = const_cast<char*>("CD");
            iovs[0].iov_len = 2;
            auto strData = std::move(p->toString());
            iovs[1].iov_base = strData.data();
            iovs[1].iov_len = strData.size();
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

        return true;
    }

    uint64_t PromptUser(std::string_view public_key, void* arg) EXCLUDES(mutex_) {
        uint64_t id = NextId();

        std::lock_guard<std::mutex> lock(mutex_);
        pending_prompts_.emplace_back(id, public_key, arg);
        DispatchPendingPrompt();
        return id;
    }

    // Interrupt the worker thread to do some work.
    void Interrupt() {
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
    std::unordered_map<uint64_t, std::string> keys_ GUARDED_BY(mutex_);

    // We keep two separate queues: one to handle backpressure from the socket (output_queue_)
    // and one to make sure we only dispatch one authrequest at a time (pending_prompts_).
    std::deque<AdbdWifiPacket> output_queue_;

    std::optional<std::tuple<uint64_t, std::string, void*>> dispatched_prompt_ GUARDED_BY(mutex_);
    std::deque<std::tuple<uint64_t, std::string, void*>> pending_prompts_ GUARDED_BY(mutex_);
};  // struct AdbdWifiContext

// static
const AdbdWifiContext::QueryHandler AdbdWifiContext::kQueries[] = {
        {"QN", &AdbdWifiContext::queryGetDeviceName},
        {"SN", &AdbdWifiContext::querySetDeviceName},
        {"QD", &AdbdWifiContext::queryPairedDevicesList},
        {"QP", &AdbdWifiContext::queryPairingDevicesList},
        {"PA", &AdbdWifiContext::queryPairDevice},
        {"UP", &AdbdWifiContext::queryUnpairDevice},
        {"CP", &AdbdWifiContext::queryCancelPairing},
        {"ED", &AdbdWifiContext::queryEnableDiscovery},
        {"DD", &AdbdWifiContext::queryDisableDiscovery},
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

void adbd_wifi_get_public_keys(AdbdWifiContext* ctx,
                               bool (*callback)(const char* public_key, size_t len, void* arg),
                               void* arg) {
    ctx->IteratePublicKeys(callback, arg);
}

uint64_t adbd_wifi_notify_auth(AdbdWifiContext* ctx, const char* public_key, size_t len) {
    return ctx->NotifyAuthenticated(std::string_view(public_key, len));
}

void adbd_wifi_notify_disconnect(AdbdWifiContext* ctx, uint64_t id) {
    return ctx->NotifyDisconnected(id);
}

void adbd_wifi_pairing_code(AdbdWifiContext* ctx,
                            const char* pairing_code,
                            uint64_t device_id,
                            void (*callback)(uint64_t device_id, bool isCorrect)) {
    ctx->responsePairingCode(pairing_code, device_id, callback);
}

bool adbd_wifi_supports_feature(AdbdWifiFeature) {
    return false;
}
