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
    std::vector<uint8_t> msg;
    explicit AdbdWifiPacketPairingCode(std::string_view public_key,
                                       const uint8_t* encrypted,
                                       uint64_t encrypted_size,
                                       uint64_t device_id) {
        PLOG(WARNING) << __func__ << " encrypted_size=" << encrypted_size
                      << " public_key=" << public_key
                      << " device_id=" << device_id;
        // The format of the msg is: <encrypted>\n<device_id>\n<public_key>
        msg.insert(msg.end(), encrypted, encrypted + encrypted_size);
        msg.push_back('\n');
        uint8_t* p8 = reinterpret_cast<uint8_t*>(&device_id);
        msg.insert(msg.end(), p8, p8 + sizeof(device_id));
        msg.push_back('\n');
        msg.insert(msg.end(), public_key.data(), public_key.data() + public_key.size());
        PLOG(WARNING) << "Constructed AdbdWifiPacketPairingCode(sz=" << msg.size() << ")";
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
    uint64_t NextPairingId() { return next_pairing_id_++; }

    void DispatchPairingRequest() REQUIRES(mutex_) {
        if (dispatched_pairing_request_) {
            // Already a pairing auth if flight. Have to wait until system
            // server gives us the ACK.
            PLOG(WARNING) << __func__ << ": another pairing request already in flight. Placing in pending queue";
            return;
        }

        if (pending_pairing_requests_.empty()) {
            // No pairing authorizations to process.
            PLOG(WARNING) << __func__ << ": No pending pairing requests to process.";
            return;
        }

        auto [id, encryptedCode, public_key] = std::move(pending_pairing_requests_.front());
        pending_pairing_requests_.pop_front();

        this->output_queue_.emplace_back(
                AdbdWifiPacketPairingCode(public_key, encryptedCode.data(), encryptedCode.size(), id));
        Interrupt();
        dispatched_pairing_request_ = std::make_tuple(id, std::move(encryptedCode), public_key);
    }

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
        PLOG(WARNING) << __func__ << ": framework_fd=" << framework_fd_.get() << ", new_fd=" << new_fd.get();
        if (framework_fd_ != -1) {
            PLOG(WARNING) << __func__ << ": Cleaning up old fd events";
            dispatched_prompt_.reset();
            dispatched_pairing_request_.reset();
            CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, framework_fd_.get(), nullptr));
            framework_fd_.reset();
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
    static void dumpBytes(const char* name, const uint8_t* bytes, uint64_t szBytes) {
        LOG(INFO) << __func__ << "(name=" << name << " sz=" << szBytes << ")";
        LOG(INFO) << "======================================";
        std::stringstream output;
        const uint64_t numBytesPerLine = 8;
        for (uint64_t i = 0; i < szBytes;) {
            for (uint64_t j = 0; j < numBytesPerLine; ++j) {
                if (i == szBytes) {
                    break;
                }
                output << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(bytes[i]);
                output << ' ';
                ++i;
            }
            if (i < szBytes) {
                output << '\n';
            }
        }
        LOG(INFO) << output.str();
        LOG(INFO) << "======================================";
    }
    // Response handlers
    void responsePairingCode(std::string_view public_key,
                             const uint8_t* encryptedCode,
                             uint64_t sizeBytes,
                             std::function<void(std::string_view public_key, bool isCorrect)> callback) EXCLUDES(mutex_) {
//        UNUSED(encryptedCode);
//        UNUSED(sizeBytes);

        CHECK_GE(sizeBytes, 0LU);
        CHECK(encryptedCode);

        PLOG(WARNING) << __func__;
        LOG(INFO) << __func__ << "public_key=" << public_key;
        dumpBytes("encryptedCode", encryptedCode, sizeBytes);
        std::lock_guard<std::mutex> lock(mutex_);
        // TODO: Need to pass the public key here so we know which device sent
        // the correct pairing code.
        // TODO: remove this once we have the keystore in place.
        uint64_t id = NextPairingId();
        std::vector<uint8_t> code;
        code.insert(code.end(), encryptedCode, encryptedCode + sizeBytes);
        dumpBytes("code", code.data(), code.size());
        pending_pairing_requests_.emplace_back(id, std::move(code), public_key);
        DispatchPairingRequest();

        // TODO: call |callback| once we are notified from system_server.
        PLOG(ERROR) << "Need to call the callback for pairing code";
        std::thread([&public_key, &callback]() {
            callback(public_key, false);
        }).detach();
        LOG(INFO) << "Unlock responsePairingCode";
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
        PLOG(WARNING) << __func__ << " output_queue_.size=" << output_queue_.size();
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
            PLOG(WARNING) << "Received AdbdWifiPacketPairingCode";
            iovs[0].iov_base = const_cast<char*>("CD");
            iovs[0].iov_len = 2;
            iovs[1].iov_base = p->msg.data();
            iovs[1].iov_len = p->msg.size();
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

    uint64_t PromptUser(std::string_view public_key, void* arg) EXCLUDES(mutex_) {
        uint64_t id = NextId();

        std::lock_guard<std::mutex> lock(mutex_);
        pending_prompts_.emplace_back(id, public_key, arg);
        DispatchPendingPrompt();
        return id;
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
    std::atomic<uint64_t> next_pairing_id_;
    AdbdWifiCallbacksV1 callbacks_;

    std::mutex mutex_;
    std::unordered_map<uint64_t, std::string> keys_ GUARDED_BY(mutex_);

    // We keep two separate queues: one to handle backpressure from the socket (output_queue_)
    // and one to make sure we only dispatch one authrequest at a time (pending_prompts_).
    // and one to make sure we only dispatch one pairing code authorization at a
    // time (dispatched_pairing_request_).
    std::deque<AdbdWifiPacket> output_queue_;

    // (device_id, encrypted_code, encrypted_code_size)
    std::optional<std::tuple<uint64_t, std::vector<uint8_t>, std::string>> dispatched_pairing_request_ GUARDED_BY(mutex_);
    std::deque<std::tuple<uint64_t, std::vector<uint8_t>, std::string>> pending_pairing_requests_ GUARDED_BY(mutex_);
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

bool adbd_wifi_pairing_code(AdbdWifiContext* ctx,
                            const char* public_key,
                            const uint8_t* encrypted_code,
                            uint64_t size_bytes) {
    PLOG(WARNING) << __func__;
//    UNUSED(ctx);
//    UNUSED(public_key);
//    UNUSED(encrypted_code);
//    UNUSED(size_bytes);
    std::condition_variable cv;
    std::mutex mutex;
    bool success = false;
    auto callback = [&](std::string_view public_key, bool result) {
        UNUSED(public_key);
        LOG(WARNING) << "Got pairing code auth callback";
        std::unique_lock<std::mutex> lock(mutex);
        success = result;
        cv.notify_all();
    };
    ctx->responsePairingCode(public_key, encrypted_code, size_bytes, callback);
    LOG(ERROR) << __func__ << " waiting for cv";
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock);
    LOG(ERROR) << __func__ << " triggered on cv";

    return success;
//    return true;
}

bool adbd_wifi_supports_feature(AdbdWifiFeature) {
    return false;
}
