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

#include <android-base/stringprintf.h>
#include <input/VelocityTracker.h>
#include <math.h>

#include <chrono>
#include <optional>

namespace android {

constexpr int32_t DISPLAY_ID = ADISPLAY_ID_DEFAULT; // default display id

constexpr uint32_t DEFAULT_POINTER_ID = 0; // pointer ID used for manually defined tests

// velocity must be in the range (1-tol)*EV <= velocity <= (1+tol)*EV
// here EV = expected value, tol = VELOCITY_TOLERANCE
constexpr float VELOCITY_TOLERANCE = 0.2;

// estimate coefficients must be within 0.001% of the target value
constexpr float COEFFICIENT_TOLERANCE = 0.00001;

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

static std::optional<uint32_t> getChangingPointerId(BitSet32 pointers, BitSet32 otherPointers) {
    BitSet32 difference(pointers.value ^ otherPointers.value);
    uint32_t pointerId = difference.clearFirstMarkedBit();
    if (difference.value == 0U) {
        return pointerId;
    } else {
        return std::nullopt;
    }
}

static std::optional<int32_t> resolveAction(const std::vector<Position>& lastPositions,
                                            const std::vector<Position>& currentPositions,
                                            const std::vector<Position>& nextPositions) {
    BitSet32 pointers = getValidPointers(currentPositions);
    const uint32_t pointerCount = pointers.count();

    BitSet32 lastPointers = getValidPointers(lastPositions);
    const uint32_t lastPointerCount = lastPointers.count();
    if (lastPointerCount < pointerCount) {
        // A new pointer is down
        std::optional<uint32_t> pointerId = getChangingPointerId(pointers, lastPointers);
        if (pointerId == std::nullopt) {
            return std::nullopt;
        }
        return AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerId.value() << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    BitSet32 nextPointers = getValidPointers(nextPositions);
    const uint32_t nextPointerCount = nextPointers.count();
    if (pointerCount > nextPointerCount) {
        // An existing pointer is leaving
        std::optional<uint32_t> pointerId = getChangingPointerId(pointers, nextPointers);
        if (pointerId == std::nullopt) {
            return std::nullopt;
        }
        return AMOTION_EVENT_ACTION_POINTER_UP |
                (pointerId.value() << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    return AMOTION_EVENT_ACTION_MOVE;
}

} // namespace android