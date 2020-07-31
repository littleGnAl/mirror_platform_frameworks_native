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

#pragma once

#include <unordered_map>
#include <variant>

#include <android/frameworks/adpf/BnAdpfService.h>
#include <utils/Mutex.h>

namespace android::frameworks::adpf {

class AdpfService : public BnAdpfService {
public:
    AdpfService();

    static const char* getServiceName() {
        return "adpfservice";
    }

    IBinder* onAsBinder() override { return this; }

    using PipelineId = int64_t;

    binder::Status createPipeline(const std::vector<PipelineStage>& concurrentStages,
                                  int64_t stageDurationMicros, PipelineId* outId) override;
    binder::Status attachEglContext(PipelineId id, int64_t context) override;
    binder::Status attachVkCommandBuffer(PipelineId id, int64_t commandBuffer) override;
    binder::Status destroyPipeline(PipelineId id) override;

    binder::Status reportCpuCompletionTime(
        int64_t pipelineId,
        const std::vector<int64_t>& durationPerStageMicros) override;
    binder::Status reportGpuCompletionTime(int64_t pipelineId, int64_t durationMicros);

    binder::Status hintLowLatency(const std::vector<int32_t>& lowLatencyTids) override;

    enum class Unit : int32_t {
        CPU = 1,
        GPU = 2,
    };

    enum class Direction : int32_t {
        LOWER = 1,
        HIGHER = 2,
        MUCH_HIGHER = 3,
    };

    binder::Status hintLoadChange(int32_t unit, int32_t direction) override;

    enum class Mode : int32_t {
        UNSPECIFIED = 0,
        LOADING = 1,
        RUNNING = 2,
        PAUSED = 3,
    };

    binder::Status hintMode(int32_t mode, int64_t majorPhase, int32_t minorPhase) override;

    binder::Status allowAppSpecificOptimizations(bool enable) override;
    binder::Status permitFidelityDegradation(bool enable) override;

    status_t dump(int, const Vector<String16>&) override;

private:
    struct PipelineDescriptor {
        PipelineDescriptor(int uid, PipelineId id, std::vector<PipelineStage> concurrentStages,
                           std::chrono::microseconds stageDuration)
          : uid(uid), id(id), concurrentStages(std::move(concurrentStages)), stageDuration(stageDuration) {}

        std::string toString() const;

        const int uid;
        const PipelineId id;
        const std::vector<PipelineStage> concurrentStages;
        const std::chrono::microseconds stageDuration;
        std::optional<int64_t> eglContext;
        std::optional<int64_t> vkCommandBuffer;
    };

    std::mutex mMutex;
    PipelineId mNextPipelineId GUARDED_BY(mMutex) = 1;
    std::unordered_map<PipelineId, PipelineDescriptor> mPipelines GUARDED_BY(mMutex);

    using PipelineIter = decltype(mPipelines)::iterator;
    using PipelineOrError = std::variant<PipelineDescriptor*, binder::Status>;
    PipelineOrError getPipeline(PipelineId id) REQUIRES(mMutex);

};

} // namespace android::frameworks::adpf
