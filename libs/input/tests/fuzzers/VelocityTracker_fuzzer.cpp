/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>

#include "../common/VelocityTrackerHelper.h"

using namespace std::chrono_literals;
using android::base::StringPrintf;

namespace android {

static constexpr uint32_t MOTION_EVENT_MAX_LENGTH = 1000;
static constexpr uint32_t POSITION_MAX_LENGTH = 20;
static constexpr uint32_t XPOSITION_MAX = 5000;
static constexpr uint32_t YPOSITION_MAX = 5000;

// Different strategies
const char* LSQ2_STRATEGY = "lsq2";
const char* IMPULSE_STRATEGY = "impulse";
const char* LSQ3_STRATEGY = "lsq3";
const char* WLSQ2_DELTA_STRATEGY = "wlsq2-delta";
const char* WLSQ2_CENTRAL_STRATEGY = "wlsq2-central";
const char* WLSQ2_RECENT_STRATEGY = "wlsq2-recent";
const char* INT1_STRATEGY = "int1";
const char* INT2_STRATEGY = "int2";
const char* LEGACY_STRATEGY = "legacy";

static std::vector<MotionEvent> createMotionEventStream(
        const std::vector<MotionEventEntry>& motions) {
    std::vector<MotionEvent> events;
    for (size_t i = 0; i < motions.size(); i++) {
        const MotionEventEntry& entry = motions[i];
        BitSet32 pointers = getValidPointers(entry.positions);
        const uint32_t pointerCount = pointers.count();

        int32_t action;
        if (i == 0) {
            action = AMOTION_EVENT_ACTION_DOWN;
        } else if (i == motions.size() - 1) {
            action = AMOTION_EVENT_ACTION_UP;
        } else {
            const MotionEventEntry& previousEntry = motions[i - 1];
            const MotionEventEntry& nextEntry = motions[i + 1];
            std::optional<uint32_t> taction =
                    resolveAction(previousEntry.positions, entry.positions, nextEntry.positions);
            action = taction.value_or(AMOTION_EVENT_ACTION_MOVE);
        }

        PointerCoords coords[pointerCount];
        PointerProperties properties[pointerCount];
        uint32_t pointerIndex = 0;
        while (!pointers.isEmpty()) {
            uint32_t pointerId = pointers.clearFirstMarkedBit();

            coords[pointerIndex].clear();
            // We are treating column positions as pointerId

            coords[pointerIndex].setAxisValue(AMOTION_EVENT_AXIS_X, entry.positions[pointerId].x);
            coords[pointerIndex].setAxisValue(AMOTION_EVENT_AXIS_Y, entry.positions[pointerId].y);

            properties[pointerIndex].id = pointerId;
            properties[pointerIndex].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
            pointerIndex++;
        }

        MotionEvent event;
        event.initialize(0 /*deviceId*/, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, action,
                         0 /*actionButton*/, 0 /*flags*/, AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE,
                         0 /*buttonState*/, MotionClassification::NONE, 0 /*xOffset*/,
                         0 /*yOffset*/, 0 /*xPrecision*/, 0 /*yPrecision*/, 0 /*downTime*/,
                         entry.eventTime.count(), pointerCount, properties, coords);

        events.push_back(event);
    }

    return events;
}

static void computeVelocity(const char* strategy, const std::vector<MotionEventEntry>& motions) {
    VelocityTracker vt(strategy);
    float Vx, Vy;

    std::vector<MotionEvent> events = createMotionEventStream(motions);
    for (MotionEvent event : events) {
        vt.addMovement(&event);
    }

    vt.getVelocity(DEFAULT_POINTER_ID, &Vx, &Vy);
}

static void computeQuadraticEstimate(const char* strategy,
                                     const std::vector<MotionEventEntry>& motions) {
    VelocityTracker vt(strategy);
    std::vector<MotionEvent> events = createMotionEventStream(motions);
    for (MotionEvent event : events) {
        vt.addMovement(&event);
    }
    VelocityTracker::Estimator estimator;
    vt.getEstimator(0, &estimator);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    u_int32_t vectorSize = fdp.ConsumeIntegralInRange<u_int32_t>(0, MOTION_EVENT_MAX_LENGTH);

    std::vector<MotionEventEntry> motions;

    // To prevent potential integer overflow, make this value smaller by dividing by 1000.
    uint64_t bTime = fdp.ConsumeIntegral<uint64_t>() / 1000;
    std::chrono::nanoseconds baseTime = std::chrono::nanoseconds(bTime);

    for (size_t i = 1; i < vectorSize; i++) {
        MotionEventEntry mEventEntry;
        std::vector<Position> positions;

        uint16_t offTime = fdp.ConsumeIntegral<uint16_t>();
        std::chrono::nanoseconds offsetTime = std::chrono::nanoseconds(offTime);

        uint32_t positionsCount = fdp.ConsumeIntegralInRange<uint32_t>(0, POSITION_MAX_LENGTH);
        for (size_t j = 0; j < positionsCount; j++) {
            float x = fdp.ConsumeFloatingPointInRange<float>(0, XPOSITION_MAX);
            float y = fdp.ConsumeFloatingPointInRange<float>(0, YPOSITION_MAX);
            Position pos;
            pos.x = x;
            pos.y = y;
            if (!pos.isValid()) {
                continue;
            }
            positions.push_back(pos);
        }

        mEventEntry.eventTime = baseTime + offsetTime;
        baseTime = mEventEntry.eventTime;
        mEventEntry.positions = positions;

        motions.push_back(mEventEntry);
    }

    if (motions.empty()) {
        return 0;
    }

    // Fuzzing is done using each strategy
    std::vector<const char*> strategies = {
            LSQ2_STRATEGY,        IMPULSE_STRATEGY,       LSQ3_STRATEGY,
            WLSQ2_DELTA_STRATEGY, WLSQ2_CENTRAL_STRATEGY, WLSQ2_RECENT_STRATEGY,
            INT1_STRATEGY,        INT2_STRATEGY,          LEGACY_STRATEGY,
    };

    uint32_t randomStrategyIndex = fdp.ConsumeIntegralInRange<uint32_t>(0, strategies.size() - 1);

    computeVelocity(strategies[randomStrategyIndex], motions);
    computeQuadraticEstimate(strategies[randomStrategyIndex], motions);

    return 0;
}

} // namespace android