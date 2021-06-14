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

#pragma once

#include <stddef.h>
#include <cstdint>

#include <optional>
#include <ostream>
#include <string>
#include <variant>
#include <vector>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>

namespace android {

// avoid optimizations
void zeroMemory(uint8_t* data, size_t size);

class Pipe {
public:
    static std::variant<Pipe, int /* errno */> make();
    Pipe(Pipe&&) = default;
    Pipe& operator=(Pipe&&) = default;
    android::base::unique_fd& readEnd() { return mRead; }
    android::base::unique_fd& writeEnd() { return mWrite; }

private:
    Pipe() = default;
    android::base::unique_fd mRead;
    android::base::unique_fd mWrite;
};

struct ExecuteError {
    int code; // errno
    std::string message;

    explicit ExecuteError(std::string msg) : ExecuteError(errno, std::move(msg)) {}
    explicit ExecuteError(int codeArg, std::string msg) : code(codeArg), message(std::move(msg)) {}
    [[nodiscard]] std::string toString() const;
};
std::ostream& operator<<(std::ostream& os, const ExecuteError& res);

struct CommandResult {
    std::optional<int32_t> exitCode;
    std::optional<int32_t> signal;
    std::optional<pid_t> pid;
    std::string stdout;
    std::string stderr;

    std::optional<Pipe> outPipe;
    std::optional<Pipe> errPipe;

    CommandResult() = default;
    CommandResult(CommandResult&& other) noexcept { (*this) = std::move(other); }
    CommandResult& operator=(CommandResult&& other) noexcept {
        std::swap(exitCode, other.exitCode);
        std::swap(signal, other.signal);
        std::swap(pid, other.pid);
        std::swap(stdout, other.stdout);
        std::swap(stderr, other.stderr);
        return *this;
    }
    [[nodiscard]] std::string toString() const;
    ~CommandResult();

private:
    DISALLOW_COPY_AND_ASSIGN(CommandResult);
};

std::ostream& operator<<(std::ostream& os, const CommandResult& res);

using ExecuteResult = std::variant<CommandResult, ExecuteError>;

// This function assumes that, when a given predicate
// |end| finishes, the child process does not emit any other
// messages.
//
// If this is not the case, caller to execute()
// must handle these I/O in the pipes in the returned
// CommandResult object. Otherwise the child program may
// hang on I/O.
ExecuteResult execute(std::vector<std::string> argStringVec,
                      const std::function<bool(const CommandResult&)>& end);
} // namespace android
