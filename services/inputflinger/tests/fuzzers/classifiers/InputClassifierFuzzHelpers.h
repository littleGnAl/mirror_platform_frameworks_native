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
#ifndef FUZZ_INPUTCLASSIFIERHELPERS_H
#define FUZZ_INPUTCLASSIFIERHELPERS_H

#include <fuzzer/FuzzedDataProvider.h>
#include "InputClassifierConverter.h"

namespace android {

NotifyMotionArgs generateFuzzedMotionArgs(FuzzedDataProvider *tester) {
    // Create a basic motion event for testing
    PointerProperties properties;
    properties.id = 0;
    properties.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, tester->ConsumeFloatingPoint<float>());
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, tester->ConsumeFloatingPoint<float>());
    coords.setAxisValue(AMOTION_EVENT_AXIS_SIZE, tester->ConsumeFloatingPoint<float>());
    static constexpr nsecs_t downTime = 2;
    NotifyMotionArgs motionArgs(tester->ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                downTime /*eventTime*/,
                                tester->ConsumeIntegral<int32_t>() /*deviceId*/, AINPUT_SOURCE_ANY,
                                ADISPLAY_ID_DEFAULT,
                                tester->ConsumeIntegral<uint32_t>() /*policyFlags*/,
                                AMOTION_EVENT_ACTION_DOWN,
                                tester->ConsumeIntegral<int32_t>() /*actionButton*/,
                                tester->ConsumeIntegral<int32_t>() /*flags*/, AMETA_NONE,
                                tester->ConsumeIntegral<int32_t>() /*buttonState*/,
                                MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE,
                                tester->ConsumeIntegral<uint32_t>() /*deviceTimestamp*/,
                                1 /*pointerCount*/, &properties, &coords,
                                tester->ConsumeFloatingPoint<float>() /*xPrecision*/,
                                tester->ConsumeFloatingPoint<float>() /*yPrecision*/, downTime,
                                {} /*videoFrames*/);
    return motionArgs;
}

float getMotionEventAxis(hardware::input::common::V1_0::PointerCoords coords,
                         hardware::input::common::V1_0::Axis axis) {
    uint32_t index = BitSet64::getIndexOfBit(static_cast<uint64_t>(coords.bits),
                                             static_cast<uint64_t>(axis));
    return coords.values[index];
}

} // namespace android

#endif // FUZZ_INPUTCLASSIFIERHELPERS_H
