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

binder::Status AdpfService::createPipeline(const std::vector<PipelineStage>& concurrentStages,
                                           int64_t stageDurationMicros, int64_t* outId) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    std::lock_guard lock(mMutex);
    const PipelineId id = mNextPipelineId++;
    const PipelineDescriptor descriptor{uid, id, concurrentStages,
                                  std::chrono::microseconds(stageDurationMicros)};
    ALOGI("createPipeline created:");
    ALOGI("%s", descriptor.toString().c_str());
    mPipelines.emplace(std::make_pair(id, std::move(descriptor)));
    *outId = id;
    return binder::Status::ok();
}

binder::Status AdpfService::attachEglContext(PipelineId id, int64_t context) {
    std::lock_guard lock(mMutex);
    const auto pipelineOrError = getPipeline(id);
    if (std::holds_alternative<binder::Status>(pipelineOrError)) {
        return std::get<binder::Status>(pipelineOrError);
    }
    const auto pipeline = std::get<PipelineDescriptor*>(pipelineOrError);

    ALOGI("attaching EGLContext 0x%" PRIx64 " to pipeline %" PRId64, context, id);
    pipeline->eglContext = context;
    // GPU resources are mutually exclusive
    pipeline->vkCommandBuffer = std::nullopt;
    return binder::Status::ok();
}

binder::Status AdpfService::attachVkCommandBuffer(PipelineId id, int64_t commandBuffer) {
    std::lock_guard lock(mMutex);
    const auto pipelineOrError = getPipeline(id);
    if (std::holds_alternative<binder::Status>(pipelineOrError)) {
        return std::get<binder::Status>(pipelineOrError);
    }
    const auto pipeline = std::get<PipelineDescriptor*>(pipelineOrError);

    ALOGI("attaching VkCommandBuffer 0x%" PRIx64 " to pipeline %" PRId64, commandBuffer, id);
    pipeline->vkCommandBuffer = commandBuffer;
    // GPU resources are mutually exclusive
    pipeline->eglContext = std::nullopt;
    return binder::Status::ok();
}

binder::Status AdpfService::destroyPipeline(PipelineId id) {
    std::lock_guard lock(mMutex);
    const auto pipelineOrError = getPipeline(id);
    if (std::holds_alternative<binder::Status>(pipelineOrError)) {
        return std::get<binder::Status>(pipelineOrError);
    }

    ALOGI("destroying pipeline %" PRId64, id);
    mPipelines.erase(id);
    return binder::Status::ok();
}

binder::Status AdpfService::reportCpuCompletionTime(PipelineId id, const std::vector<int64_t>& durationPerStageMicros) {
    std::lock_guard lock(mMutex);
    const auto pipelineOrError = getPipeline(id);
    if (std::holds_alternative<binder::Status>(pipelineOrError)) {
        return std::get<binder::Status>(pipelineOrError);
    }

    std::string durations = "[";
    bool first = true;
    for (int64_t stageDurationMicros : durationPerStageMicros) {
        if (!first) {
            durations.append(", ");
        }
        durations.append(base::StringPrintf("%" PRId64 " us", stageDurationMicros));
        first = false;
    }
    durations.append("]");

    ALOGI("pipeline %" PRId64 " reported CPU completion times: %s", id, durations.c_str());
    return binder::Status::ok();
}

binder::Status AdpfService::reportGpuCompletionTime(PipelineId id, int64_t durationMicros) {
    std::lock_guard lock(mMutex);
    const auto pipelineOrError = getPipeline(id);
    if (std::holds_alternative<binder::Status>(pipelineOrError)) {
        return std::get<binder::Status>(pipelineOrError);
    }

    ALOGI("pipeline %" PRId64 " reported GPU completion time: %" PRId64 " us", id, durationMicros);
    return binder::Status::ok();
}

binder::Status AdpfService::hintLowLatency(const std::vector<int>& lowLatencyTids) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    std::string tids = "[";
    bool first = true;
    for (int tid : lowLatencyTids) {
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

binder::Status AdpfService::hintMode(int32_t intMode, int64_t majorPhase, int32_t minorPhase) {
    auto mode = tryModeFromInt(intMode);
    if (!mode) {
        return binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Invalid mode %d", intMode).c_str());
    }

    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("received mode from uid %d: %s major %" PRId64 " (0x%" PRIx64 ") minor %d (%#x)", uid,
            to_string(*mode).c_str(), majorPhase, majorPhase, minorPhase, minorPhase);
    return binder::Status::ok();
}

binder::Status AdpfService::allowAppSpecificOptimizations(bool enable) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("uid %d requests %s app-specific optimizations", uid,
            enable ? "allowing" : "disallowing");
    return binder::Status::ok();
}

binder::Status AdpfService::permitFidelityDegradation(bool enable) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    ALOGI("uid %d requests %s fidelity degradation", uid,
            enable ? "permitting" : "disallowing");
    return binder::Status::ok();
}

status_t AdpfService::dump(int, const Vector<String16>&) {
    ALOGI("hello from dump");
    return OK;
}

std::string AdpfService::PipelineDescriptor::toString() const {
    std::string out = base::StringPrintf("pipeline %" PRId64 " for uid %d\n", id, uid);
    const int64_t stageDurationMicros = stageDuration.count();
    out.append(base::StringPrintf("  stageDuration: %" PRId64 "us\n", stageDurationMicros));
    out.append("  concurrentStages:\n");
    for (const PipelineStage& stage : concurrentStages) {
        std::string tidList = "    [";
        bool first = true;
        for (const int32_t tid : stage.participatingTids) {
            if (!first) {
                tidList.append(", ");
            }
            tidList.append(std::to_string(tid));
            first = false;
        }
        tidList.append("]");
        out.append(tidList);
    }
    if (eglContext) {
        out.append("  eglContext: 0x%" PRIx64, *eglContext);
    } else if (vkCommandBuffer) {
        out.append("  vkCommandBuffer: 0x%" PRIx64, *vkCommandBuffer);
    } else {
        out.append("  no GPU resources");
    }
    return out;
}

AdpfService::PipelineOrError AdpfService::getPipeline(PipelineId id) {
    const auto pipelineIter = mPipelines.find(id);
    if (pipelineIter == mPipelines.end()) {
        return PipelineOrError{
                binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Unknown pipeline id %" PRId64, id).c_str())};
    }

    PipelineDescriptor* const pipeline = &(pipelineIter->second);

    const IPCThreadState* const ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();

    if (pipeline->uid != uid) {
        return PipelineOrError{
                binder::Status::fromExceptionCode(
                binder::Status::EX_ILLEGAL_ARGUMENT,
                base::StringPrintf("Invalid pipeline id %" PRId64 " for uid %d", id, uid).c_str())};
    }

    return PipelineOrError{pipeline};
}

} // namespace android::frameworks::adpf
