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

    using StageId = int64_t;

    binder::Status createStage(const std::vector<int>& threadIds, int64_t desiredDurationMicros,
                               StageId* outId) override;
    binder::Status attachEglContext(StageId id, int64_t context) override;
    binder::Status attachVkCommandBuffer(StageId id, int64_t commandBuffer) override;
    binder::Status destroyStage(StageId id) override;

    binder::Status reportCpuCompletionTime(StageId stageId, int64_t actualDurationMicros) override;
    binder::Status reportGpuCompletionTime(StageId stageId, int64_t actualDurationMicros) override;

    binder::Status hintLowLatency(const std::vector<int32_t>& threadIds) override;

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

    binder::Status hintMode(int32_t mode, int64_t majorPhase, int64_t minorPhase) override;

    binder::Status allowAppSpecificOptimizations(bool enable) override;
    binder::Status allowFidelityDegradation(bool enable) override;

    status_t dump(int, const Vector<String16>&) override;

private:
    struct StageDescriptor {
        StageDescriptor(int uid, StageId id, std::vector<int> threadIds,
                        std::chrono::microseconds duration)
          : uid(uid), id(id), threadIds(std::move(threadIds)), duration(duration) {}

        std::string toString() const;

        const int uid;
        const StageId id;
        const std::vector<int> threadIds;
        const std::chrono::microseconds duration;
        std::optional<int64_t> eglContext;
        std::optional<int64_t> vkCommandBuffer;
    };

    std::mutex mMutex;
    StageId mNextStageId GUARDED_BY(mMutex) = 1;
    std::unordered_map<StageId, StageDescriptor> mStages GUARDED_BY(mMutex);

    using StageIter = decltype(mStages)::iterator;
    using StageOrError = std::variant<StageDescriptor*, binder::Status>;
    StageOrError getStage(StageId id) REQUIRES(mMutex);

};

} // namespace android::frameworks::adpf
