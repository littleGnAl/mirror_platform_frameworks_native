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

#include <android-base/expected.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>

namespace android {

// avoid optimizations
void zeroMemory(uint8_t* data, size_t size);

struct ExecuteError {
    int code; // errno
    std::string message;

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

    android::base::unique_fd outPipe;
    android::base::unique_fd errPipe;

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

    [[nodiscard]] bool stdoutEndsWithNewLine() const {
        return !stdout.empty() && stdout.back() == '\n';
    }

private:
    DISALLOW_COPY_AND_ASSIGN(CommandResult);
};

std::ostream& operator<<(std::ostream& os, const CommandResult& res);

using ExecuteResult = android::base::expected<CommandResult, ExecuteError>;
std::ostream& operator<<(std::ostream& os, const ExecuteResult& res);

// Execute a command using tokens specified in @a argStringVec.
//
// @a end is a predicate checked periodically when the command emits any output to stdout or
// stderr. When it is evaluated to false, the function returns immediately even though
// the child process has not been terminated. The function also assumes that, after @a end
// is evaluated to true, the child process does not emit any other messages.
// If this is not the case, caller to execute() must handle these I/O in the pipes in the returned
// CommandResult object. Otherwise the child program may hang on I/O.
//
// If @a end is nullptr, it is equivalent to a predicate that always returns false. In this
// case, execute() returns after the child process is terminated.
//
// If @a end is evaluated to true, and execute() returns with the child process running,
// the returned CommandResult has pid, outPipe, and errPipe set. In this case, the caller is
// responsible for holding the returned CommandResult. When the CommandResult object is destroyed,
// the child process is killed.
//
// On the other hand, execute() returns with the child process terminated, either exitCode or signal
// is set.
//
// If the parent process has encountered any errors for system calls, return ExecuteError with
// the proper errno set.
ExecuteResult execute(std::vector<std::string> argStringVec,
                      const std::function<bool(const CommandResult&)>& end);
} // namespace android
