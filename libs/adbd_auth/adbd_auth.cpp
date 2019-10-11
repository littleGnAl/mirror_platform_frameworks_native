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

#include "include/adbd_auth.h"

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
#include <cutils/sockets.h>

#include "include/adbd_framework.h"

struct AdbdAuthPacketAuthenticated {
    std::string public_key;
};

struct AdbdAuthPacketDisconnected {
    std::string public_key;
};

struct AdbdAuthPacketRequestAuthorization {
    std::string public_key;
};

using AdbdAuthPacket = std::variant<AdbdAuthPacketAuthenticated, AdbdAuthPacketDisconnected,
                                    AdbdAuthPacketRequestAuthorization>;

struct AdbdAuthContext : public AdbdFramework {
public:
    explicit AdbdAuthContext(AdbdAuthCallbacksV1* callbacks) :
        AdbdFramework("adbd"),
        next_id_(0),
        callbacks_(*callbacks) { }

    AdbdAuthContext(const AdbdAuthContext& copy) = delete;
    AdbdAuthContext(AdbdAuthContext&& move) = delete;
    AdbdAuthContext& operator=(const AdbdAuthContext& copy) = delete;
    AdbdAuthContext& operator=(AdbdAuthContext&& move) = delete;

    uint64_t NextId() { return next_id_++; }

    void DispatchPendingPrompt() REQUIRES(mutex_) {
        if (dispatched_prompt_) {
            LOG(INFO) << "adbd_auth: prompt currently pending, skipping";
            return;
        }

        if (pending_prompts_.empty()) {
            LOG(INFO) << "adbd_auth: no prompts to send";
            return;
        }

        LOG(INFO) << "adbd_auth: prompting user for adb authentication";
        auto [id, public_key, arg] = std::move(pending_prompts_.front());
        pending_prompts_.pop_front();

        this->output_queue_.emplace_back(
                AdbdAuthPacketRequestAuthorization{.public_key = public_key});

        Interrupt();
        dispatched_prompt_ = std::make_tuple(id, public_key, arg);
    }

    virtual void FrameworkConnected() override {
        // Nothing to do here.
    }

    virtual void FrameworkDisconnected() override EXCLUDES(mutex_) {
        std::lock_guard<std::mutex> lock(mutex_);
        output_queue_.clear();
        dispatched_prompt_.reset();
    }

    virtual bool HasPacketForWriting() override EXCLUDES(mutex_) {
        std::lock_guard<std::mutex> lock(mutex_);
        return !output_queue_.empty();
    }

    virtual bool HandlePacket(std::string_view packet) override REQUIRES(mutex_) {
        LOG(INFO) << "received packet: " << packet;

        if (packet.length() < 2) {
          LOG(ERROR) << "received packet of invalid length";
          return false;
        }

        if (packet[0] == 'O' && packet[1] == 'K') {
          CHECK(this->dispatched_prompt_.has_value());
          auto& [id, key, arg] = *this->dispatched_prompt_;
          keys_.emplace(id, std::move(key));

          this->callbacks_.key_authorized(arg, id);
          this->dispatched_prompt_ = std::nullopt;
        } else if (packet[0] == 'N' && packet[1] == 'O') {
          CHECK_EQ(2UL, packet.length());
          // TODO: Do we want a callback if the key is denied?
          this->dispatched_prompt_ = std::nullopt;
          DispatchPendingPrompt();
        } else {
          LOG(ERROR) << "unhandled packet: " << packet;
          return false;
        }

        return true;
    }

    virtual std::optional<AdbFrameworkPkt> FetchPacket() override REQUIRES(mutex_) {
        if (output_queue_.empty()) {
            return std::nullopt;
        }

        auto& packet = output_queue_.front();
        std::string code;
        std::string data;

        if (auto* p = std::get_if<AdbdAuthPacketAuthenticated>(&packet)) {
            code = "CK";
            data = std::move(p->public_key);
        } else if (auto* p = std::get_if<AdbdAuthPacketDisconnected>(&packet)) {
            code = "DC";
            data = std::move(p->public_key);
        } else if (auto* p = std::get_if<AdbdAuthPacketRequestAuthorization>(&packet)) {
            code = "PK";
            data = std::move(p->public_key);
        } else {
            LOG(FATAL) << "unhandled packet type?";
        }

        output_queue_.pop_front();

        return std::make_tuple(std::move(code), std::move(data));
    }

    static constexpr const char* key_paths[] = {"/adb_keys", "/data/misc/adb/adb_keys"};
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

    uint64_t PromptUser(std::string_view public_key, void* arg) EXCLUDES(mutex_) {
        uint64_t id = NextId();

        std::lock_guard<std::mutex> lock(mutex_);
        pending_prompts_.emplace_back(id, public_key, arg);
        DispatchPendingPrompt();
        return id;
    }

    uint64_t NotifyAuthenticated(std::string_view public_key) EXCLUDES(mutex_) {
        uint64_t id = NextId();
        std::lock_guard<std::mutex> lock(mutex_);
        keys_.emplace(id, public_key);
        output_queue_.emplace_back(
                AdbdAuthPacketDisconnected{.public_key = std::string(public_key)});
        return id;
    }

    void NotifyDisconnected(uint64_t id) EXCLUDES(mutex_) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(id);
        if (it == keys_.end()) {
            LOG(DEBUG) << "couldn't find public key to notify disconnection, skipping";
            return;
        }
        output_queue_.emplace_back(AdbdAuthPacketDisconnected{.public_key = std::move(it->second)});
        keys_.erase(it);
    }

    std::atomic<uint64_t> next_id_;
    AdbdAuthCallbacksV1 callbacks_;

    std::mutex mutex_;
    std::unordered_map<uint64_t, std::string> keys_ GUARDED_BY(mutex_);

    // We keep two separate queues: one to handle backpressure from the socket (output_queue_)
    // and one to make sure we only dispatch one authrequest at a time (pending_prompts_).
    std::deque<AdbdAuthPacket> output_queue_ GUARDED_BY(mutex_);

    std::optional<std::tuple<uint64_t, std::string, void*>> dispatched_prompt_ GUARDED_BY(mutex_);
    std::deque<std::tuple<uint64_t, std::string, void*>> pending_prompts_ GUARDED_BY(mutex_);
};

AdbdAuthContext* adbd_auth_new(AdbdAuthCallbacks* callbacks) {
    if (callbacks->version != 1) {
      LOG(ERROR) << "received unknown AdbdAuthCallbacks version " << callbacks->version;
      return nullptr;
    }

    return new AdbdAuthContext(&callbacks->callbacks.v1);
}

void adbd_auth_delete(AdbdAuthContext* ctx) {
    delete ctx;
}

void adbd_auth_run(AdbdAuthContext* ctx) {
    ctx->Run();
}

void adbd_auth_get_public_keys(AdbdAuthContext* ctx,
                               bool (*callback)(const char* public_key, size_t len, void* arg),
                               void* arg) {
    ctx->IteratePublicKeys(callback, arg);
}

uint64_t adbd_auth_notify_auth(AdbdAuthContext* ctx, const char* public_key, size_t len) {
    return ctx->NotifyAuthenticated(std::string_view(public_key, len));
}

void adbd_auth_notify_disconnect(AdbdAuthContext* ctx, uint64_t id) {
    ctx->NotifyDisconnected(id);
}

void adbd_auth_prompt_user(AdbdAuthContext* ctx, const char* public_key, size_t len,
                               void* arg) {
    ctx->PromptUser(std::string_view(public_key, len), arg);
}

bool adbd_auth_supports_feature(AdbdAuthFeature) {
    return false;
}
