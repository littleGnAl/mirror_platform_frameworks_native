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
    if (difference.value != 0U) {
        ALOGE("Only 1 pointer can enter or leave at a time");
        return std::nullopt;
    }
    return pointerId;
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

static std::optional<std::vector<MotionEvent>> createMotionEventStream(
        const std::vector<MotionEventEntry>& motions) {
    if (motions.empty()) {
        ALOGE("Need at least 1 sample to create a MotionEvent. Received empty vector.");
        return std::nullopt;
    }

    std::vector<MotionEvent> events;
    for (size_t i = 0; i < motions.size(); i++) {
        const MotionEventEntry& entry = motions[i];
        BitSet32 pointers = getValidPointers(entry.positions);
        const uint32_t pointerCount = pointers.count();

        int32_t action;
        if (i == 0) {
            action = AMOTION_EVENT_ACTION_DOWN;
            if (pointerCount != 1U) {
                ALOGE("First event should only have 1 pointer");
                return std::nullopt;
            }
        } else if (i == motions.size() - 1) {
            if (pointerCount != 1U) {
                ALOGE("Last event should only have 1 pointer");
                return std::nullopt;
            }
            action = AMOTION_EVENT_ACTION_UP;
        } else {
            const MotionEventEntry& previousEntry = motions[i - 1];
            const MotionEventEntry& nextEntry = motions[i + 1];

            std::optional<uint32_t> resolvedAction =
                    resolveAction(previousEntry.positions, entry.positions, nextEntry.positions);
            if (resolvedAction == std::nullopt) {
                return std::nullopt;
            }
            action = resolvedAction.value();
        }

        PointerCoords coords[pointerCount];
        PointerProperties properties[pointerCount];
        uint32_t pointerIndex = 0;
        while (!pointers.isEmpty()) {
            uint32_t pointerId = pointers.clearFirstMarkedBit();

            coords[pointerIndex].clear();
            // We are treating column positions as pointerId
            if (!entry.positions[pointerId].isValid()) {
                ALOGE("The entry at pointerId must be valid");
                return std::nullopt;
            }
            coords[pointerIndex].setAxisValue(AMOTION_EVENT_AXIS_X, entry.positions[pointerId].x);
            coords[pointerIndex].setAxisValue(AMOTION_EVENT_AXIS_Y, entry.positions[pointerId].y);

            properties[pointerIndex].id = pointerId;
            properties[pointerIndex].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
            pointerIndex++;
        }
        if (pointerIndex != pointerCount) {
            ALOGE("pointerIndex and pointerCount does not match");
            return std::nullopt;
        }
        MotionEvent event;
        event.initialize(0 /*deviceId*/, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID, action,
                         0 /*actionButton*/, 0 /*flags*/, AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE,
                         0 /*buttonState*/, MotionClassification::NONE, 0 /*xOffset*/,
                         0 /*yOffset*/, 0 /*xPrecision*/, 0 /*yPrecision*/, 0 /*downTime*/,
                         entry.eventTime.count(), pointerCount, properties, coords);

        events.push_back(event);
    }

    return events;
}
} // namespace android