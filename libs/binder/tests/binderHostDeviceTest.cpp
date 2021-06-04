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

using ::android::base::ErrnoError;
using ::android::base::Error;
using ::android::base::ParseBool;
using ::android::base::ParseBoolResult;
using ::android::base::ReadFdToString;
using ::android::base::ReadFileToString;
using ::android::base::Result;
using ::android::base::Split;
using ::android::base::StringPrintf;
using ::android::base::Trim;
using ::android::base::testing::HasValue;
using ::android::base::testing::Ok;
using ::std::string_literals::operator""s;
using ::testing::AllOf;
using ::testing::ContainsRegex;
using ::testing::ExplainMatchResult;
using ::testing::Value;

namespace android {

struct CommandResult {
    int32_t exitCode;
    std::string stdout;
    std::string stderr;
};
void PrintTo(const CommandResult& res, std::ostream* os) {
    *os << "code=" << res.exitCode << ", stdout=" << res.stdout << ", stderr=" << res.stderr;
}

namespace {

// e.g. EXPECT_THAT(expr, StatusEq(OK)) << "additional message";
MATCHER_P(StatusEq, expected, (negation ? "not " : "") + statusToString(expected)) {
    *result_listener << statusToString(arg);
    return expected == arg;
}
// e.g. EXPECT_THAT(CommandResult{0}, ExitCode(0))
MATCHER_P(ExitCode, codeMatcher, "") {
    return ExplainMatchResult(codeMatcher, arg.exitCode, result_listener);
}
MATCHER_P(Stdout, stdoutMatcher, "") {
    return ExplainMatchResult(stdoutMatcher, arg.stdout, result_listener);
}

// Execute shell command with fork / execvp / waitpid.
// If command is executed and terminated properly from end of main() or exit(), returns
// the exit code, stdout and stderr.
// Otherwise return some error.
Result<CommandResult> execute(std::vector<std::string> argStringVec) {
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
    int status;
    if (waitpid(pid, &status, 0) == -1) return ErrnoError() << "waitpid(" << pid << ")";
    if (!WIFEXITED(status)) return Error() << "WIFEXITED(" << status << ") is false";

    CommandResult ret;
    ret.exitCode = WEXITSTATUS(status);
    (void)close(stdout.release());
    if (!ReadFileToString(stdout.path, &ret.stdout)) return ErrnoError() << "read(stdout)";
    (void)close(stderr.release());
    if (!ReadFileToString(stderr.path, &ret.stderr)) return ErrnoError() << "read(stderr)";
    return ret;
}

// Naive wrapper of execute(vector<string>). It doesn't work if there are spaces in tokens.
Result<CommandResult> execute(const std::string& command) {
    return execute(android::base::Split(command, " "));
}

// Test that runs servicedispatcher directly.
class ServiceDispatcherTest : public ::testing::Test {
public:
    static constexpr const char* kServiceName = "stats";
    static constexpr const char* kProcessName = "statsd";

    static void SetUpTestSuite() {
        // TODO(b/182914638) fix selinux permissions properly
        auto getenforce = execute("adb shell getenforce");
        ASSERT_THAT(getenforce, HasValue(ExitCode(0)));
        if ("Enforcing" == Trim(getenforce->stdout)) sEnforcing = true;
        EXPECT_THAT(execute("adb shell setenforce 0"), HasValue(ExitCode(0)));
    }
    static void TearDownTestSuite() {
        if (!sEnforcing) return;
        EXPECT_THAT(execute("adb shell setenforce 1"), HasValue(ExitCode(0)));
    }

    void SetUp() override {
        auto debuggableResult = execute("adb shell getprop ro.debuggable");
        ASSERT_THAT(debuggableResult, HasValue(ExitCode(0)));
        auto debuggableBool = ParseBool(Trim(debuggableResult->stdout));
        ASSERT_NE(ParseBoolResult::kError, debuggableBool) << Trim(debuggableResult->stdout);
        if (debuggableBool == ParseBoolResult::kFalse)
            GTEST_SKIP() << "ro.debuggable=" << Trim(debuggableResult->stdout);

        // Wait 3s until statsd comes alive.
        auto statsRegex = StringPrintf(R"(\b%s:\s+\[(.+)\])", kServiceName);
        auto hasStats = HasValue(AllOf(ExitCode(0), Stdout(ContainsRegex(statsRegex))));
        Result<CommandResult> result;
        for (int i = 0; i < 3; ++i) {
            result = execute("adb shell service list");
            if (Value(result, hasStats)) break;
            sleep(1);
        }
        EXPECT_THAT(result, hasStats) << "stats service is not found.";

        std::smatch match;
        ASSERT_TRUE(std::regex_search(result->stdout, match, std::regex(statsRegex)));
        mInterfaceName = match[1];
    }
    void TearDown() override {
        if (mHostPort != 0) {
            EXPECT_THAT(execute({"adb", "forward", "--remove", "tcp:" + std::to_string(mHostPort)}),
                        HasValue(ExitCode(0)));
        }

        // TODO(b/182914638) shut down RPC server properly
        auto pidResult = execute({"adb", "shell", "pidof", kProcessName});
        ASSERT_THAT(pidResult, HasValue(ExitCode(0)));
        ASSERT_FALSE(pidResult->stdout.empty());
        ASSERT_THAT(execute({"adb", "shell", "kill", "-9", Trim(pidResult->stdout).c_str()}),
                    HasValue(ExitCode(0)));
    }

    unsigned int mHostPort = 0;
    std::string mInterfaceName;

private:
    static bool sEnforcing;
};
bool ServiceDispatcherTest::sEnforcing = false;

TEST_F(ServiceDispatcherTest, PingAndInterfaceName) {
    auto dispatchResult = execute({"adb", "shell", "servicedispatcher", kServiceName});
    ASSERT_THAT(dispatchResult, HasValue(ExitCode(0)));
    unsigned int devicePort;
    ASSERT_TRUE(android::base::ParseUint(Trim(dispatchResult->stdout), &devicePort))
            << "\"" << Trim(dispatchResult->stdout) << "\" is not a valid device port number";

    auto forwardResult = execute({"adb", "forward", "tcp:0", "tcp:" + std::to_string(devicePort)});
    ASSERT_THAT(forwardResult, HasValue(ExitCode(0)));
    ASSERT_TRUE(android::base::ParseUint(Trim(forwardResult->stdout), &mHostPort))
            << "\"" << Trim(forwardResult->stdout) << "\" is not a valid host port number";

    auto rpcSession = RpcSession::make();
    ASSERT_TRUE(rpcSession->setupInetClient("127.0.0.1", mHostPort));
    auto rpcBinder = rpcSession->getRootObject();
    ASSERT_NE(nullptr, rpcBinder);

    EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
    EXPECT_EQ(String16(mInterfaceName.data(), mInterfaceName.size()),
              rpcBinder->getInterfaceDescriptor());
}

} // namespace
} // namespace android
