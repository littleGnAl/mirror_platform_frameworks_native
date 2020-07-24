/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <input/VelocityTracker.h>
#include <math.h>

#include <chrono>

using namespace std::chrono_literals;
using android::base::StringPrintf;

#define MOTION_EVENT_MAX_LENGTH 1000
#define POSITION_MAX_LENGTH 20

namespace android {

constexpr int32_t DISPLAY_ID = ADISPLAY_ID_DEFAULT; // default display id

constexpr int32_t DEFAULT_POINTER_ID = 0; // pointer ID used for manually defined tests

// Extracted from VelocityTracker_test.cpp

struct Position {
    float x;
    float y;

    bool isValid() const { return !(isnan(x) && isnan(y)); }
};

struct MotionEventEntry {
    std::chrono::nanoseconds eventTime;
    std::vector<Position> positions;
};

static BitSet32 getValidPointers(const std::vector<Position>& positions) {
    BitSet32 pointers;
    for (size_t i = 0; i < positions.size(); i++) {
        if (positions[i].isValid()) {
            pointers.markBit(i);
        }
    }
    return pointers;
}

static uint32_t getChangingPointerId(BitSet32 pointers, BitSet32 otherPointers) {
    BitSet32 difference(pointers.value ^ otherPointers.value);
    uint32_t pointerId = difference.clearFirstMarkedBit();
    return pointerId;
}

static int32_t resolveAction(const std::vector<Position>& lastPositions,
                             const std::vector<Position>& currentPositions,
                             const std::vector<Position>& nextPositions) {
    BitSet32 pointers = getValidPointers(currentPositions);
    const uint32_t pointerCount = pointers.count();

    BitSet32 lastPointers = getValidPointers(lastPositions);
    const uint32_t lastPointerCount = lastPointers.count();
    if (lastPointerCount < pointerCount) {
        // A new pointer is down
        uint32_t pointerId = getChangingPointerId(pointers, lastPointers);
        return AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerId << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    BitSet32 nextPointers = getValidPointers(nextPositions);
    const uint32_t nextPointerCount = nextPointers.count();
    if (pointerCount > nextPointerCount) {
        // An existing pointer is leaving
        uint32_t pointerId = getChangingPointerId(pointers, nextPointers);
        return AMOTION_EVENT_ACTION_POINTER_UP |
                (pointerId << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    return AMOTION_EVENT_ACTION_MOVE;
}

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
            action = resolveAction(previousEntry.positions, entry.positions, nextEntry.positions);
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
        event.initialize(0 /*deviceId*/, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID, action,
                         0 /*actionButton*/, 0 /*flags*/, AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE,
                         0 /*buttonState*/, MotionClassification::NONE, 0 /*xOffset*/,
                         0 /*yOffset*/, 0 /*xPrecision*/, 0 /*yPrecision*/, 0 /*downTime*/,
                         entry.eventTime.count(), pointerCount, properties, coords);

        events.emplace_back(event);
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
    FuzzedDataProvider tester(data, size);

    u_int32_t vectorSize = tester.ConsumeIntegralInRange<u_int32_t>(0, MOTION_EVENT_MAX_LENGTH);

    std::vector<MotionEventEntry> motions;

    // To make this time more realistic we can divide it by 1000. It is nano seconds from boot.
    uint64_t bTime = tester.ConsumeIntegral<uint64_t>() / 1000;
    std::chrono::nanoseconds baseTime =
            std::chrono::nanoseconds(static_cast<std::chrono::nanoseconds::rep>(bTime));

    for (size_t i = 1; i < vectorSize; i++) {
        MotionEventEntry mEventEntry;
        std::vector<Position> positions;

        uint16_t offTime = tester.ConsumeIntegral<uint16_t>();
        std::chrono::nanoseconds offsetTime =
                std::chrono::nanoseconds(static_cast<std::chrono::nanoseconds::rep>(offTime));

        uint32_t positionsCount = tester.ConsumeIntegralInRange<uint32_t>(0, POSITION_MAX_LENGTH);
        for (size_t j = 0; j < positionsCount; j++) {
            float x = tester.ConsumeFloatingPointInRange<float>(0, 5000);
            float y = tester.ConsumeFloatingPointInRange<float>(0, 5000);
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

    computeVelocity("impulse", motions);
    computeVelocity("lsq2", motions);

    computeQuadraticEstimate("impulse", motions);
    computeQuadraticEstimate("lsq2", motions);

    return 0;
}

} // namespace android