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

#include <fuzzer/FuzzedDataProvider.h>
#include "InputReaderBase.h"
#include "tests/fuzzers/commonHeaders/InputReaderHelperClasses.h"

static constexpr size_t kMaxRangeSize = 650;

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider tester(data, size);

    sp<FakeInputReaderPolicy> mFakePolicy = new FakeInputReaderPolicy();
    // Viewports_GetByPort
    constexpr ViewportType type = ViewportType::VIEWPORT_EXTERNAL;
    std::string uniqueId1 = tester.ConsumeRandomLengthString(50);
    std::string uniqueId2 = tester.ConsumeRandomLengthString(50);
    int32_t displayId1 = tester.ConsumeIntegralInRange(0, 10);
    int32_t displayId2 = tester.ConsumeIntegralInRange(0, 10);
    uint8_t hdmi1 = tester.ConsumeIntegralInRange(0, 861);
    uint8_t hdmi2 = tester.ConsumeIntegralInRange(313, 1001);
    uint8_t hdmi3 = tester.ConsumeIntegralInRange(1337, 2480);
    mFakePolicy->clearViewports();
    // Add a viewport that's associated with some display port that's not of interest.
    mFakePolicy->addDisplayViewport(displayId1,
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, uniqueId1, hdmi3, type);
    // Add another viewport, connected to HDMI1 port
    mFakePolicy->addDisplayViewport(displayId2,
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, uniqueId2, hdmi1, type);
    // Check that correct display viewport was returned by comparing the display ports.
    std::optional<DisplayViewport> hdmi1Viewport = mFakePolicy->getDisplayViewportByPort(hdmi1);

    // Check that we can still get the same viewport using the uniqueId
    hdmi1Viewport = mFakePolicy->getDisplayViewportByUniqueId(uniqueId2);

    // Check that we cannot find a port with "HDMI2", because we never added one
    std::optional<DisplayViewport> hdmi2Viewport = mFakePolicy->getDisplayViewportByPort(hdmi2);

    mFakePolicy.clear();

    return 0;
}

} // namespace android