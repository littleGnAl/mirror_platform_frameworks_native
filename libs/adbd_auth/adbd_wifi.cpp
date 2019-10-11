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
#include <cutils/sockets.h>

#include "include/adbd_framework.h"

#define DEBUGON 1

struct AdbdWifiPacketConnected {
    std::string guid;
};

struct AdbdWifiPacketDisconnected {
    std::string guid;
};

struct AdbdWifiPacketServerConnected {
    std::string port;
};

struct AdbdWifiPacketServerDisconnected {
    std::string port;
};

using AdbdWifiPacket = std::variant<AdbdWifiPacketConnected,
                                    AdbdWifiPacketDisconnected,
                                    AdbdWifiPacketServerConnected,
                                    AdbdWifiPacketServerDisconnected>;

struct AdbdWifiContext : AdbdFramework {
public:
    explicit AdbdWifiContext(AdbdWifiCallbacksV1* callbacks) :
        AdbdFramework("adbdwifi"),
        next_id_(0),
        callbacks_(*callbacks) { }

    AdbdWifiContext(const AdbdWifiContext& copy) = delete;
    AdbdWifiContext(AdbdWifiContext&& move) = delete;
    AdbdWifiContext& operator=(const AdbdWifiContext& copy) = delete;
    AdbdWifiContext& operator=(AdbdWifiContext&& move) = delete;

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

    void NotifyTlsServerConnected(int port) EXCLUDES(mutex_) {
        // Just translate port to a string so we don't have to do byte
        // format translation.
        std::lock_guard<std::mutex> lock(mutex_);
        output_queue_.emplace_back(
                AdbdWifiPacketServerConnected{.port = std::to_string(port)});
        Interrupt();
    }

    void NotifyTlsServerDisconnected(int port) EXCLUDES(mutex_) {
        // Just translate port to a string so we don't have to do byte
        // format translation.
        std::lock_guard<std::mutex> lock(mutex_);
        output_queue_.emplace_back(
                AdbdWifiPacketServerDisconnected{.port = std::to_string(port)});
        Interrupt();
    }

private:
    static constexpr const char* key_paths[] = {"/adb_wifi_keys", "/data/misc/adb/adb_wifi_keys"};

    uint64_t NextId() { return next_id_++; }

    virtual bool HasPacketForWriting() override EXCLUDES(mutex_) {
        std::lock_guard<std::mutex> lock(mutex_);
        return !output_queue_.empty();
    }

    virtual void FrameworkDisconnected() override EXCLUDES(mutex_) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            output_queue_.clear();
            guids_.clear();
        }
        callbacks_.on_framework_disconnected();
    }

    virtual void FrameworkConnected() override {
        callbacks_.on_framework_connected();
    }

    virtual bool HandlePacket(std::string_view packet) override REQUIRES(mutex_) {
        LOG(INFO) << "received packet: [" << packet << "]";

        if (packet.length() < 2) {
            LOG(ERROR) << "received packet of invalid length";
            return false;
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
        }
        return handledPacket;
    }

    virtual std::optional<AdbFrameworkPkt> FetchPacket() override REQUIRES(mutex_) {
        if (output_queue_.empty()) {
            return std::nullopt;
        }

        auto& packet = output_queue_.front();
        std::string code;
        std::string data;
        if (auto* p = std::get_if<AdbdWifiPacketConnected>(&packet)) {
            code = "CN";
            data = std::move(p->guid);
        } else if (auto* p = std::get_if<AdbdWifiPacketDisconnected>(&packet)) {
            code = "DC";
            data = std::move(p->guid);
        } else if (auto* p = std::get_if<AdbdWifiPacketServerConnected>(&packet)) {
            code = "SC";
            data = std::move(p->port);
        } else if (auto* p = std::get_if<AdbdWifiPacketServerDisconnected>(&packet)) {
            code = "SD";
            data = std::move(p->port);
        } else {
            LOG(FATAL) << "unhandled packet type?";
        }
        output_queue_.pop_front();

        return std::make_tuple(std::move(code), std::move(data));
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

private:
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
    ctx->Run();
}

uint64_t adbd_wifi_notify_connected(AdbdWifiContext* ctx, const char* guid, size_t len) {
    return ctx->NotifyConnected(std::string_view(guid, len));
}

void adbd_wifi_notify_disconnected(AdbdWifiContext* ctx, uint64_t id) {
    ctx->NotifyDisconnected(id);
}

void adbd_wifi_notify_server_connected(AdbdWifiContext* ctx, int port) {
    ctx->NotifyTlsServerConnected(port);
}

void adbd_wifi_notify_server_disconnected(AdbdWifiContext* ctx, int port) {
    ctx->NotifyTlsServerDisconnected(port);
}

bool adbd_wifi_supports_feature(AdbdWifiFeature) {
    return false;
}
