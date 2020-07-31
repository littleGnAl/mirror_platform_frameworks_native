/*
 * Copyright 2020 The Android Open Source Project
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

#include <cinttypes>

#include <android-base/stringprintf.h>
#include <binder/IPCThreadState.h>
#include <log/log.h>

#include "AdpfService.h"

using namespace std::string_literals;

namespace android::frameworks::adpf {

AdpfService::AdpfService() {
    ALOGI("hello from AdpfService");
}

binder::Status AdpfService::createStage(const std::vector<int>& threadIds,
                                        int64_t stageDurationMicros, int64_t* outId) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    std::lock_guard lock(mMutex);
    const StageId id = mNextStageId++;
    const StageDescriptor descriptor{uid, id, threadIds,
                                  std::chrono::microseconds(stageDurationMicros)};
    ALOGI("createStage created:");
    ALOGI("%s", descriptor.toString().c_str());
    mStages.emplace(std::make_pair(id, std::move(descriptor)));
    *outId = id;
    return binder::Status::ok();
}

binder::Status AdpfService::attachEglContext(StageId id, int64_t context) {
    std::lock_guard lock(mMutex);
    const auto stageOrError = getStage(id);
    if (std::holds_alternative<binder::Status>(stageOrError)) {
        return std::get<binder::Status>(stageOrError);
    }
    const auto stage = std::get<StageDescriptor*>(stageOrError);

    ALOGI("attaching EGLContext 0x%" PRIx64 " to stage %" PRId64, context, id);
    stage->eglContext = context;
    // GPU resources are mutually exclusive
    stage->vkCommandBuffer = std::nullopt;
    return binder::Status::ok();
}

binder::Status AdpfService::attachVkCommandBuffer(StageId id, int64_t commandBuffer) {
    std::lock_guard lock(mMutex);
    const auto stageOrError = getStage(id);
    if (std::holds_alternative<binder::Status>(stageOrError)) {
        return std::get<binder::Status>(stageOrError);
    }
    const auto stage = std::get<StageDescriptor*>(stageOrError);

    ALOGI("attaching VkCommandBuffer 0x%" PRIx64 " to stage %" PRId64, commandBuffer, id);
    stage->vkCommandBuffer = commandBuffer;
    // GPU resources are mutually exclusive
    stage->eglContext = std::nullopt;
    return binder::Status::ok();
}

binder::Status AdpfService::destroyStage(StageId id) {
    std::lock_guard lock(mMutex);
    const auto stageOrError = getStage(id);
    if (std::holds_alternative<binder::Status>(stageOrError)) {
        return std::get<binder::Status>(stageOrError);
    }

    ALOGI("destroying stage %" PRId64, id);
    mStages.erase(id);
    return binder::Status::ok();
}

binder::Status AdpfService::reportCpuCompletionTime(StageId id, int64_t actualDurationMicros) {
    std::lock_guard lock(mMutex);
    const auto stageOrError = getStage(id);
    if (std::holds_alternative<binder::Status>(stageOrError)) {
        return std::get<binder::Status>(stageOrError);
    }

    ALOGI("stage %" PRId64 " reported CPU completion time: %" PRId64 " us", id,
            actualDurationMicros);
    return binder::Status::ok();
}

binder::Status AdpfService::reportGpuCompletionTime(StageId id, int64_t actualDurationMicros) {
    std::lock_guard lock(mMutex);
    const auto stageOrError = getStage(id);
    if (std::holds_alternative<binder::Status>(stageOrError)) {
        return std::get<binder::Status>(stageOrError);
    }

    ALOGI("stage %" PRId64 " reported GPU completion time: %" PRId64 " us", id,
            actualDurationMicros);
    return binder::Status::ok();
}

binder::Status AdpfService::hintLowLatency(const std::vector<int>& threadIds) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    std::string tids = "[";
    bool first = true;
    for (int tid : threadIds) {
        if (!first) {
            tids.append(", ");
        }
        tids.append(base::StringPrintf("%d", tid));
        first = false;
    }
    tids.append("]");
    
    ALOGI("received low latency tids %s from uid %d", tids.c_str(), uid);
    return binder::Status::ok();
}

namespace {
std::optional<AdpfService::Unit> tryUnitFromInt(int32_t intUnit) {
    if (intUnit < 1 || intUnit > 2) {
        return std::nullopt;
    }
    return static_cast<AdpfService::Unit>(intUnit);
}

std::string to_string(AdpfService::Unit unit) {
    switch (unit) {
        case AdpfService::Unit::CPU: return "CPU"s;
        case AdpfService::Unit::GPU: return "GPU"s;
    }
}

std::optional<AdpfService::Direction> tryDirectionFromInt(int32_t intDirection) {
    if (intDirection < 1 || intDirection > 3) {
        return std::nullopt;
    }
    return static_cast<AdpfService::Direction>(intDirection);
}

std::string to_string(AdpfService::Direction direction) {
    switch (direction) {
        case AdpfService::Direction::LOWER: return "LOWER"s;
        case AdpfService::Direction::HIGHER: return "HIGHER"s;
        case AdpfService::Direction::MUCH_HIGHER: return "MUCH_HIGHER"s;
    }
}
}

binder::Status AdpfService::hintLoadChange(int32_t intUnit, int32_t intDirection) {
    auto unit = tryUnitFromInt(intUnit);
    if (!unit) {
        return binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Invalid unit %d", intUnit).c_str());
    }

    auto direction = tryDirectionFromInt(intDirection);
    if (!direction) {
        return binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Invalid direction %d", intDirection).c_str());
    }


    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("received load change %s for %s from uid %d", to_string(*direction).c_str(),
            to_string(*unit).c_str(), uid);
    return binder::Status::ok();
}

namespace {
std::optional<AdpfService::Mode> tryModeFromInt(int32_t intMode) {
    if (intMode < 0 || intMode > 3) {
        return std::nullopt;
    }
    return static_cast<AdpfService::Mode>(intMode);
}

std::string to_string(AdpfService::Mode mode) {
    switch (mode) {
        case AdpfService::Mode::UNSPECIFIED: return "UNSPECIFIED"s;
        case AdpfService::Mode::LOADING: return "LOADING"s;
        case AdpfService::Mode::RUNNING: return "RUNNING"s;
        case AdpfService::Mode::PAUSED: return "PAUSED"s;
    }
}
}

binder::Status AdpfService::hintMode(int32_t intMode, int64_t majorPhase, int64_t minorPhase) {
    auto mode = tryModeFromInt(intMode);
    if (!mode) {
        return binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Invalid mode %d", intMode).c_str());
    }

    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("received mode from uid %d: %s "
            "major %" PRId64 " (0x%" PRIx64 ") "
            "minor %" PRId64 " (0x%" PRIx64 ") ",
            uid, to_string(*mode).c_str(), majorPhase, majorPhase, minorPhase, minorPhase);
    return binder::Status::ok();
}

binder::Status AdpfService::allowAppSpecificOptimizations(bool enable) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("uid %d requests %s app-specific optimizations", uid,
            enable ? "allowing" : "disallowing");
    return binder::Status::ok();
}

binder::Status AdpfService::allowFidelityDegradation(bool enable) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("uid %d requests %s fidelity degradation", uid,
            enable ? "allowing" : "disallowing");
    return binder::Status::ok();
}

status_t AdpfService::dump(int, const Vector<String16>&) {
    ALOGI("hello from dump");
    return OK;
}

std::string AdpfService::StageDescriptor::toString() const {
    std::string out = base::StringPrintf("stage %" PRId64 " for uid %d\n", id, uid);
    const int64_t stageDurationMicros = duration.count();
    out.append(base::StringPrintf("  duration: %" PRId64 " us\n", stageDurationMicros));
    out.append("  threadIds: [");

    bool first = true;
    for (int tid : threadIds) {
        if (!first) {
            out.append(", ");
        }
        out.append(std::to_string(tid));
        first = false;
    }
    out.append("]\n");

    if (eglContext) {
        out.append("  eglContext: 0x%" PRIx64, *eglContext);
    } else if (vkCommandBuffer) {
        out.append("  vkCommandBuffer: 0x%" PRIx64, *vkCommandBuffer);
    } else {
        out.append("  no GPU resources");
    }
    return out;
}

AdpfService::StageOrError AdpfService::getStage(StageId id) {
    const auto stageIter = mStages.find(id);
    if (stageIter == mStages.end()) {
        return StageOrError{
                binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Unknown stage id %" PRId64, id).c_str())};
    }

    StageDescriptor* const stage = &(stageIter->second);

    const IPCThreadState* const ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    if (stage->uid != uid) {
        return StageOrError{
                binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Invalid stage id %" PRId64 " for uid %d", id, uid).c_str())};
    }

    return StageOrError{stage};
}

} // namespace android::frameworks::adpf
