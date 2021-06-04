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

// Integration test for servicedispatcher + adb forward. Requires ADB.

#include <stdlib.h>

#include <regex>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/result-gmock.h>
#include <android-base/result.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <binder/RpcSession.h>

using ::android::base::EndsWith;
using ::android::base::ErrnoError;
using ::android::base::Error;
using ::android::base::Join;
using ::android::base::ParseBool;
using ::android::base::ParseBoolResult;
using ::android::base::ParseUint;
using ::android::base::ReadFdToString;
using ::android::base::ReadFileToString;
using ::android::base::Result;
using ::android::base::Split;
using ::android::base::StartsWith;
using ::android::base::StringPrintf;
using ::android::base::StringReplace;
using ::android::base::Trim;
using ::android::base::testing::HasValue;
using ::android::base::testing::Ok;
using ::std::string_literals::operator""s;
using ::testing::AllOf;
using ::testing::ContainsRegex;
using ::testing::ExplainMatchResult;

namespace android {

struct CommandResult {
    std::optional<int32_t> exitCode;
    std::optional<int32_t> signal;
    std::optional<pid_t> pid;
    std::string stdout;
    std::string stderr;

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
    ~CommandResult() {
        if (pid.value_or(0) != 0) EXPECT_EQ(0, kill(*pid, SIGKILL)) << strerror(errno);
    }

private:
    DISALLOW_COPY_AND_ASSIGN(CommandResult);
};
std::ostream& operator<<(std::ostream& os, const CommandResult& res) {
    if (res.exitCode) os << "code=" << *res.exitCode;
    if (res.signal) os << "signal=" << *res.signal;
    if (res.pid) os << ", pid=" << *res.pid;
    return os << ", stdout=" << res.stdout << ", stderr=" << res.stderr;
}
void PrintTo(const CommandResult& res, std::ostream* os) {
    *os << res;
}

namespace {

constexpr const char* kServiceBinary = "/data/local/tmp/binderHostDeviceTest-service";
constexpr const char* kServiceName = "binderHostDeviceTestService";
constexpr const char* kDescriptor = "android.binderHostDeviceTestService";

// e.g. EXPECT_THAT(expr, StatusEq(OK)) << "additional message";
MATCHER_P(StatusEq, expected, (negation ? "not " : "") + statusToString(expected)) {
    *result_listener << statusToString(arg);
    return expected == arg;
}
// e.g. EXPECT_THAT(CommandResult{0}, ExitCode(0))
MATCHER_P(ExitCode, codeMatcher, "") {
    if (!arg.exitCode) {
        *result_listener << "no exit code";
        return false;
    }
    return ExplainMatchResult(codeMatcher, arg.exitCode, result_listener);
}
MATCHER_P(Stdout, stdoutMatcher, "") {
    return ExplainMatchResult(stdoutMatcher, arg.stdout, result_listener);
}

Result<CommandResult> executeInternal(std::vector<std::string> argStringVec,
                                      const std::function<bool(const CommandResult&)>& end) {
    // turn vector<string> into null-terminated char* vector.
    std::vector<char*> argv;
    for (auto& arg : argStringVec) argv.push_back(arg.data());
    argv.push_back(nullptr);

    TemporaryFile stdout;
    TemporaryFile stderr;

    int pid = fork();
    if (pid == -1) return ErrnoError() << "fork()";
    if (pid == 0) {
        // child
        stdout.DoNotRemove();
        if (-1 == TEMP_FAILURE_RETRY(dup2(stdout.fd, STDOUT_FILENO))) PLOG(FATAL) << "dup2(stdout)";
        (void)close(stdout.release());
        stderr.DoNotRemove();
        if (-1 == TEMP_FAILURE_RETRY(dup2(stderr.fd, STDERR_FILENO))) PLOG(FATAL) << "dup2(stderr)";
        (void)close(stderr.release());
        execvp(argv[0], argv.data());
        PLOG(FATAL) << "execvp() returns";
    }
    // parent
    (void)close(stdout.release());
    (void)close(stderr.release());

    CommandResult ret;
    ret.pid = pid;
    while (true) {
        int status;
        auto exitPid = waitpid(pid, &status, end ? WNOHANG : 0);
        if (exitPid == -1) return ErrnoError() << "waitpid(" << pid << ")";
        if (exitPid == pid) {
            if (WIFEXITED(status)) {
                ret.pid = std::nullopt;
                ret.exitCode = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                ret.pid = std::nullopt;
                ret.signal = WTERMSIG(status);
            }
        }
        if (!ReadFileToString(stdout.path, &ret.stdout)) return ErrnoError() << "read(stdout)";
        if (!ReadFileToString(stderr.path, &ret.stderr)) return ErrnoError() << "read(stderr)";
        if (!ret.pid.has_value() || (end && end(ret))) return ret;
        usleep(50 * 1000); // 50ms
    }
}

// Execute shell command
// If command is executed and terminated properly from end of main() or exit(), returns
// the exit code, stdout and stderr.
// Otherwise return some error.
Result<CommandResult> execute(std::vector<std::string> argStringVec) {
    return executeInternal(std::move(argStringVec), nullptr);
}

// Execute a long running shell command with fork / execvp / waitpid. Return if:
// - Any error;
// - The process exited;
// - The predicate "end" returns true.
Result<CommandResult> executeLongRunning(std::vector<std::string> argStringVec,
                                         const std::function<bool(const CommandResult&)>& end) {
    auto res = executeInternal(argStringVec, end);
    if (!res.ok()) return res.error();
    if (!res->pid.has_value()) return Error() << "No PID. " << *res;
    if (!end(*res)) return Error() << "Predicate fails: " << *res;
    return res;
}

bool stdoutEndsWithNewLine(const CommandResult& commandResult) {
    return EndsWith(commandResult.stdout, "\n");
}

// RAII object for servicedispatcher.
class ServiceDispatcher {
public:
    static Result<ServiceDispatcher> dispatch(const std::string& serviceName) {
        auto dispatchResult = executeLongRunning({"adb", "shell", "servicedispatcher", serviceName},
                                                 stdoutEndsWithNewLine);
        if (!dispatchResult.ok()) return dispatchResult.error();

        unsigned int devicePort;
        if (!ParseUint(Trim(dispatchResult->stdout), &devicePort))
            return Error() << "\"" << Trim(dispatchResult->stdout)
                           << "\" is not a valid device port number";

        return ServiceDispatcher(std::move(*dispatchResult), devicePort);
    }
    ~ServiceDispatcher() = default;
    ServiceDispatcher(ServiceDispatcher&& other) = default;
    [[nodiscard]] unsigned int devicePort() const { return mDevicePort; }

private:
    ServiceDispatcher(CommandResult&& commandResult, unsigned int devicePort)
          : mCommandResult(std::move(commandResult)), mDevicePort(devicePort) {}
    DISALLOW_COPY_AND_ASSIGN(ServiceDispatcher);
    CommandResult mCommandResult;
    unsigned int mDevicePort;
};

// RAII object for adb forward
class AdbForwarder {
public:
    static Result<AdbForwarder> forward(unsigned int devicePort) {
        auto forwardResult =
                execute({"adb", "forward", "tcp:0", "tcp:" + std::to_string(devicePort)});
        if (!forwardResult.ok() || forwardResult->exitCode.value_or(1) != 0)
            return Error() << "adb forward failed: " << testing::PrintToString(forwardResult);
        unsigned int hostPort;
        if (!android::base::ParseUint(Trim(forwardResult->stdout), &hostPort))
            return Error() << "\"" << Trim(forwardResult->stdout)
                           << "\" is not a valid host port number";
        return AdbForwarder(hostPort);
    }
    ~AdbForwarder() {
        if (mHostPort != 0) {
            EXPECT_THAT(execute({"adb", "forward", "--remove", "tcp:" + std::to_string(mHostPort)}),
                        HasValue(ExitCode(0)));
        }
    }

    AdbForwarder(AdbForwarder&& other) noexcept { (*this) = std::move(other); }
    AdbForwarder& operator=(AdbForwarder&& other) noexcept {
        std::swap(mHostPort, other.mHostPort);
        return *this;
    }
    [[nodiscard]] unsigned int hostPort() const { return mHostPort; }

private:
    explicit AdbForwarder(unsigned int hostPort) : mHostPort(hostPort) {}
    DISALLOW_COPY_AND_ASSIGN(AdbForwarder);
    unsigned int mHostPort;
};

// Test that runs servicedispatcher directly.
class ServiceDispatcherTest : public ::testing::Test {
public:
    void SetUp() override {
        auto debuggableResult = execute(Split("adb shell getprop ro.debuggable", " "));
        ASSERT_THAT(debuggableResult, HasValue(ExitCode(0)));
        auto debuggableBool = ParseBool(Trim(debuggableResult->stdout));
        ASSERT_NE(ParseBoolResult::kError, debuggableBool) << Trim(debuggableResult->stdout);
        if (debuggableBool == ParseBoolResult::kFalse) {
            GTEST_SKIP() << "ro.debuggable=" << Trim(debuggableResult->stdout);
        }

        auto service =
                executeLongRunning({"adb", "shell", kServiceBinary, kServiceName, kDescriptor},
                                   stdoutEndsWithNewLine);
        ASSERT_THAT(service, Ok());
        mService = std::move(*service);
    }
    void TearDown() override { mService.reset(); }

    [[nodiscard]] static sp<IBinder> get(unsigned int hostPort) {
        auto rpcSession = RpcSession::make();
        if (!rpcSession->setupInetClient("127.0.0.1", hostPort)) {
            ADD_FAILURE() << "Failed to setupInetClient on " << hostPort;
            return nullptr;
        }
        return rpcSession->getRootObject();
    }

private:
    std::optional<CommandResult> mService;
};

TEST_F(ServiceDispatcherTest, OneClient) {
    auto dispatched = ServiceDispatcher::dispatch(kServiceName);
    ASSERT_THAT(dispatched, Ok());

    auto forwarded = AdbForwarder::forward(dispatched->devicePort());
    ASSERT_THAT(forwarded, Ok());

    auto rpcBinder = get(forwarded->hostPort());
    ASSERT_NE(nullptr, rpcBinder);

    EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
    EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
}

TEST_F(ServiceDispatcherTest, TenClientsOnSamePort) {
    auto dispatched = ServiceDispatcher::dispatch(kServiceName);
    ASSERT_THAT(dispatched, Ok());

    auto forwarded = AdbForwarder::forward(dispatched->devicePort());
    ASSERT_THAT(forwarded, Ok());

    auto threadFn = [&] {
        auto rpcBinder = get(forwarded->hostPort());
        ASSERT_NE(nullptr, rpcBinder);

        EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
        EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
    };

    std::vector<std::thread> threads;
    for (size_t i = 0; i < 10; ++i) threads.emplace_back(threadFn);
    for (auto& thread : threads) thread.join();
}

TEST_F(ServiceDispatcherTest, TestClientsOnDifferentPorts) {
    auto threadFn = [&] {
        auto dispatched = ServiceDispatcher::dispatch(kServiceName);
        ASSERT_THAT(dispatched, Ok());

        auto forwarded = AdbForwarder::forward(dispatched->devicePort());
        ASSERT_THAT(forwarded, Ok());
        auto rpcBinder = get(forwarded->hostPort());
        ASSERT_NE(nullptr, rpcBinder);

        EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
        EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
    };
    std::vector<std::thread> threads;
    for (size_t i = 0; i < 10; ++i) threads.emplace_back(threadFn);
    for (auto& thread : threads) thread.join();
}

} // namespace
} // namespace android
