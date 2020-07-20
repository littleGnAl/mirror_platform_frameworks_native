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

static constexpr int32_t kMaxAxes = 64;

static NotifyMotionArgs generateFuzzedMotionArgs(FuzzedDataProvider *fdp) {
    // Create a basic motion event for testing
    PointerProperties properties;
    properties.id = 0;
    properties.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
    PointerCoords coords;
    coords.clear();
    for (int32_t i = 0; i < fdp->ConsumeIntegralInRange<int32_t>(0, kMaxAxes); i++) {
        coords.setAxisValue(fdp->ConsumeIntegral<int32_t>(), fdp->ConsumeFloatingPoint<float>());
    }

    static constexpr nsecs_t downTime = 2;
    NotifyMotionArgs motionArgs(fdp->ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                downTime /*eventTime*/,
                                fdp->ConsumeIntegral<int32_t>() /*deviceId*/, AINPUT_SOURCE_ANY,
                                ADISPLAY_ID_DEFAULT,
                                fdp->ConsumeIntegral<uint32_t>() /*policyFlags*/,
                                AMOTION_EVENT_ACTION_DOWN,
                                fdp->ConsumeIntegral<int32_t>() /*actionButton*/,
                                fdp->ConsumeIntegral<int32_t>() /*flags*/, AMETA_NONE,
                                fdp->ConsumeIntegral<int32_t>() /*buttonState*/,
                                MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE,
                                fdp->ConsumeIntegral<uint32_t>() /*deviceTimestamp*/,
                                1 /*pointerCount*/, &properties, &coords,
                                fdp->ConsumeFloatingPoint<float>() /*xPrecision*/,
                                fdp->ConsumeFloatingPoint<float>() /*yPrecision*/, downTime,
                                {} /*videoFrames*/);
    return motionArgs;
}

} // namespace android

#endif // FUZZ_INPUTCLASSIFIERHELPERS_H
