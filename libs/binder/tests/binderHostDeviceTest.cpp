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

// End-to-end tests for host-device binder communication. Requires a device and adb.

#include <stdlib.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parsebool.h>
#include <android-base/result-gmock.h>
#include <android-base/result.h>
#include <android-base/strings.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::android::base::ErrnoError;
using ::android::base::Error;
using ::android::base::ParseBool;
using ::android::base::ParseBoolResult;
using ::android::base::ReadFdToString;
using ::android::base::ReadFileToString;
using ::android::base::Result;
using ::android::base::Split;
using ::android::base::testing::HasValue;
using ::android::base::testing::Ok;
using ::testing::AllOf;
using ::testing::ContainsRegex;
using ::testing::Matches;

namespace android {

struct CommandResult {
    int32_t exitCode;
    std::string stdout;
    std::string stderr;
    std::ostream& operator<<(std::ostream& os) {
        return os << "code=" << exitCode << ", stdout=" << stdout << ", stderr=" << stderr;
    }
};

namespace {

// e.g. EXPECT_THAT(CommandResult{0}, ExitCode(0))
MATCHER_P(ExitCode, codeMatcher, "") {
    return ::testing::ExplainMatchResult(codeMatcher, arg.exitCode, result_listener);
}
MATCHER_P(Stdout, stdoutMatcher, "") {
    return ::testing::ExplainMatchResult(stdoutMatcher, arg.stdout, result_listener);
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

class BinderHostDeviceTest : public ::testing::Test {
public:
    void SetUp() override {
        auto debuggableResult = execute("adb shell getprop ro.debuggable");
        ASSERT_THAT(debuggableResult, HasValue(ExitCode(0)));
        auto boolDebuggable = ParseBool(debuggableResult->stdout);
        ASSERT_NE(ParseBoolResult::kError, boolDebuggable);
        if (boolDebuggable == ParseBoolResult::kFalse)
            GTEST_SKIP() << "ro.debuggable=" << debuggableResult->stdout;

        // Wait 10s until statsd comes alive.
        auto matcher = HasValue(AllOf(ExitCode(0), Stdout(ContainsRegex(R"(\bstats:\s+.*$)"))));
        Result<CommandResult> result;
        for (int i = 0; i < 2; ++i) {
            result = execute("adb shell service list");
            if (Matches(matcher)(result)) break;
            sleep(1);
        }
        ASSERT_THAT(result, matcher) << "stats service is not found.";
    }
    void TearDown() override {
        auto pidResult = execute("adb shell pidof statsd");
        ASSERT_THAT(pidResult, HasValue(ExitCode(0)));
        ASSERT_FALSE(pidResult->stdout.empty());
        ASSERT_THAT(execute({"adb", "shell", "kill", "-9", pidResult->stdout.c_str()}),
                    HasValue(ExitCode(0)));
    }
    unsigned int mPort;
};

TEST_F(BinderHostDeviceTest, Simple) {}

} // namespace
} // namespace android
