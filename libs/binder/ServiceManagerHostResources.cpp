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

#include "ServiceManagerHostResources.h"

#include <android-base/parseint.h>
#include <binder/RpcSession.h>

#include "Utils.h"

namespace android {

namespace {
bool stdoutEndsWithNewLine(const CommandResult& commandResult) {
    return !commandResult.stdout.empty() && commandResult.stdout.back() == '\n';
}
} // namespace

std::optional<AdbForwarder> AdbForwarder::forward(unsigned int devicePort) {
    auto executeResult =
            execute({"adb", "forward", "tcp:0", "tcp:" + std::to_string(devicePort)}, nullptr);
    if (std::holds_alternative<ExecuteError>(executeResult)) {
        ALOGE("Unable to run `adb forward tcp:0 tcp:%d`: %s", devicePort,
              std::get<ExecuteError>(executeResult).toString().c_str());
        return std::nullopt;
    }
    auto& commandResult = std::get<CommandResult>(executeResult);
    if (commandResult.exitCode.value_or(1) != 0) { // has_value() && value() == 0
        ALOGE("Unable to run `adb forward tcp:0 tcp:%d`, command exits with %s", devicePort,
              commandResult.toString().c_str());
        return std::nullopt;
    }
    auto hostPortString = commandResult.stdout;
    if (!hostPortString.empty() && hostPortString.back() == '\n')
        hostPortString = hostPortString.substr(0, hostPortString.size() - 1);
    unsigned int hostPort = 0;
    if (!android::base::ParseUint(hostPortString, &hostPort)) {
        ALOGE("Not a valid host port: %s", hostPortString.c_str());
        return std::nullopt;
    }
    if (hostPort == 0) {
        ALOGE("0 is not a valid host port");
        return std::nullopt;
    }
    return AdbForwarder(hostPort);
}

AdbForwarder& AdbForwarder::operator=(AdbForwarder&& other) noexcept {
    std::swap(mPort, other.mPort);
    return *this;
}

AdbForwarder::~AdbForwarder() {
    if (!mPort.has_value()) return;

    auto executeResult =
            execute({"adb", "forward", "--remove", "tcp:" + std::to_string(*mPort)}, nullptr);
    if (std::holds_alternative<ExecuteError>(executeResult)) {
        ALOGW("Unable to run `adb forward --remove tcp:%d`: %s", *mPort,
              std::get<ExecuteError>(executeResult).toString().c_str());
    }
    auto& commandResult = std::get<CommandResult>(executeResult);
    if (commandResult.exitCode.value_or(1) != 0) { // has_value() && value() == 0
        ALOGW("Unable to run `adb forward --remove tcp:%d`, command exits with %s", *mPort,
              commandResult.toString().c_str());
    }
    ALOGI("Successfully run `adb forward --remove tcp:%d`", *mPort);
}

ServiceManagerHostResources ServiceManagerHostResources::create() {
    ServiceManagerHostResources ret;

    auto executeResult =
            execute({"adb", "shell", "servicedispatcher", "-m"}, stdoutEndsWithNewLine);
    if (std::holds_alternative<ExecuteError>(executeResult)) {
        ALOGE("%s", std::get<ExecuteError>(executeResult).toString().c_str());
        return ret;
    }

    ret.mCommandResult = std::move(std::get<CommandResult>(executeResult));
    if (ret.mCommandResult.exitCode.value_or(0) != 0) { // !has_value() || value() == 0
        ALOGE("Command exits with: %s", ret.mCommandResult.toString().c_str());
        return ret;
    }
    if (!stdoutEndsWithNewLine(ret.mCommandResult)) {
        ALOGE("Unexpected command result: %s", ret.mCommandResult.toString().c_str());
        return ret;
    }

    std::string devicePortString =
            ret.mCommandResult.stdout.substr(0, ret.mCommandResult.stdout.size() - 1);
    unsigned int devicePort = 0;
    if (!android::base::ParseUint(devicePortString, &devicePort)) {
        int savedErrno = errno;
        ALOGE("Not a valid device port number: %s: %s", devicePortString.c_str(),
              strerror(savedErrno));
        return ret;
    }
    if (devicePort == 0) {
        ALOGE("Not a valid device port number: 0");
        return ret;
    }

    auto forwardResult = AdbForwarder::forward(devicePort);
    if (!forwardResult.has_value()) {
        return ret;
    }
    ret.mAdbForwarder = std::move(*forwardResult);
    LOG_ALWAYS_FATAL_IF(!ret.mAdbForwarder.hostPort().has_value());

    auto rpcSession = RpcSession::make();
    if (!rpcSession->setupInetClient("127.0.0.1", *ret.mAdbForwarder.hostPort())) {
        ALOGE("Unable to set up inet client on host port %u", *ret.mAdbForwarder.hostPort());
        return ret;
    }
    auto binder = rpcSession->getRootObject();
    if (binder == nullptr) {
        ALOGE("RpcSession::getRootObject returns nullptr");
        return ret;
    }
    ret.mImpl = android::os::IServiceManager::asInterface(binder);
    if (ret.mImpl == nullptr) {
        ALOGE("RpcSession::getRootObject returns object that's not IServiceManager");
    }
    return ret;
}

} // namespace android
