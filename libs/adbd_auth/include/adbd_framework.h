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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <optional>
#include <string>

#include <android-base/unique_fd.h>

// This base class represents the communication between the framework and adbd.
struct AdbdFramework {
    static constexpr uint64_t kEpollConstSocket = 0;
    static constexpr uint64_t kEpollConstEventFd = 1;
    static constexpr uint64_t kEpollConstFramework = 2;

    // (code, data)
    using AdbFrameworkPkt = std::tuple<std::string, std::string>;

public:
    explicit AdbdFramework(const char* sock_name);
    virtual ~AdbdFramework() = default;

    AdbdFramework(const AdbdFramework& copy) = delete;
    AdbdFramework(AdbdFramework&& move) = delete;
    AdbdFramework& operator=(const AdbdFramework& copy) = delete;
    AdbdFramework& operator=(AdbdFramework&& move) = delete;

    // Start the worker thread.
    void Run();

protected:
    // Interrupt the worker thread to check for data.
    void Interrupt();

    // Called when a new framework connection is made.
    virtual void FrameworkConnected() = 0;
    // Called when the framework has been disconnected.
    virtual void FrameworkDisconnected() = 0;
    // Called when new data is sent from the framework. If unable to handle
    // packet, return false. This will break the current framework connection.
    virtual bool HandlePacket(std::string_view packet) = 0;
    // Called when AdbdFramework wants to send a packet out to the framework.
    // It will call this method to fill in the next packet to send to the
    // framework. If no data is available, return nullopt.
    virtual std::optional<AdbFrameworkPkt> FetchPacket() = 0;
    // Called when AdbdFramework needs to determine if there is data to write
    // out.
    virtual bool HasPacketForWriting() = 0;

private:
    void ReplaceFrameworkFd(android::base::unique_fd new_fd);
    void UpdateFrameworkWritable();
    bool SendPacket();

    android::base::unique_fd epoll_fd_;
    android::base::unique_fd event_fd_;
    android::base::unique_fd sock_fd_;
    android::base::unique_fd framework_fd_;
};  // struct AdbdFramework
