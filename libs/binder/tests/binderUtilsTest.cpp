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

#include <sysexits.h>

#include <chrono>

#include <android-base/strings.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../Utils.h"

using testing::Optional;

namespace android {

TEST(Utils, ExecuteImmediately) {
    auto executeResult = execute({"echo", "foo"}, nullptr);
    ASSERT_TRUE(std::holds_alternative<CommandResult>(executeResult))
            << std::get<ExecuteError>(executeResult);
    auto& commandResult = std::get<CommandResult>(executeResult);
    EXPECT_THAT(commandResult.exitCode, Optional(EX_OK));
    EXPECT_EQ(commandResult.stdout, "foo\n");
}

TEST(Utils, ExecuteLongRunning) {
    auto now = std::chrono::system_clock::now();

    {
        std::vector<std::string> args{"sh", "-c",
                                      "sleep 0.5 && echo -n f && sleep 0.5 && echo oo && sleep 1"};
        auto executeResult = execute(std::move(args), [](const CommandResult& commandResult) {
            return android::base::EndsWith(commandResult.stdout, "\n");
        });
        auto elapsed = std::chrono::system_clock::now() - now;
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        EXPECT_GE(elapsedMs, 1000);
        EXPECT_LE(elapsedMs, 2000);

        ASSERT_TRUE(std::holds_alternative<CommandResult>(executeResult))
                << std::get<ExecuteError>(executeResult);
        auto& commandResult = std::get<CommandResult>(executeResult);
        EXPECT_EQ(std::nullopt, commandResult.exitCode);
        EXPECT_EQ(commandResult.stdout, "foo\n");
    }

    // ~CommandResult() called, child process is killed
    // assert that the second sleep does not finish.
    auto elapsed = std::chrono::system_clock::now() - now;
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    EXPECT_LE(elapsedMs, 2000);
}

TEST(Utils, KillWithSigKill) {
    std::vector<std::string> args{"sh", "-c", "echo foo && sleep 10"};
    auto executeResult = execute(std::move(args), [](const CommandResult& commandResult) {
        if (commandResult.pid.has_value()) {
            (void)kill(*commandResult.pid, SIGKILL);
        }
        return false;
    });

    ASSERT_TRUE(std::holds_alternative<CommandResult>(executeResult))
            << std::get<ExecuteError>(executeResult);
    auto& commandResult = std::get<CommandResult>(executeResult);
    EXPECT_EQ(std::nullopt, commandResult.exitCode);
    EXPECT_THAT(commandResult.signal, Optional(SIGKILL));
}

} // namespace android
