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

namespace android {

constexpr uint32_t DEFAULT_POINTER_ID = 1; // pointer ID used for manually defined tests

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
} // namespace android