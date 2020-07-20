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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <thread>
#include "InputReaderBase.h"
#include "tests/fuzzers/commonHeaders/InputReaderHelperClasses.h"

static constexpr size_t kMaxRangeSize = 650;

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider tester(data, size);

    sp<FakeInputReaderPolicy> mFakePolicy = new FakeInputReaderPolicy();

    // Viewports_GetCleared
    static const std::string uniqueId =
            tester.ConsumeRandomLengthString(50) + ":" + tester.ConsumeIntegralInRange<char>(0, 10);
    // We didn't add any viewports yet, so there shouldn't be any.
    std::optional<DisplayViewport> internalViewport =
            mFakePolicy->getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);
    // Add an internal viewport, then clear it
    mFakePolicy->addDisplayViewport(tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, uniqueId, NO_PORT,
                                    ViewportType::VIEWPORT_INTERNAL);
    // Check matching by uniqueId
    internalViewport = mFakePolicy->getDisplayViewportByUniqueId(uniqueId);

    // Check matching by viewport type
    internalViewport = mFakePolicy->getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);

    mFakePolicy->clearViewports();
    // Make sure nothing is found after clear
    internalViewport = mFakePolicy->getDisplayViewportByUniqueId(uniqueId);

    internalViewport = mFakePolicy->getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);

    // Viewports_GetByType
    const std::string internalUniqueId =
            tester.ConsumeRandomLengthString(50) + ":" + tester.ConsumeIntegralInRange<char>(0, 10);
    const std::string externalUniqueId =
            tester.ConsumeRandomLengthString(50) + ":" + tester.ConsumeIntegralInRange<char>(0, 10);
    const std::string virtualUniqueId1 =
            tester.ConsumeRandomLengthString(50) + ":" + tester.ConsumeIntegralInRange<char>(0, 10);
    const std::string virtualUniqueId2 =
            tester.ConsumeRandomLengthString(50) + ":" + tester.ConsumeIntegralInRange<char>(0, 10);
    constexpr int32_t virtualDisplayId1 = 2;
    constexpr int32_t virtualDisplayId2 = 3;
    // Add an internal viewport
    mFakePolicy->addDisplayViewport(tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, internalUniqueId, NO_PORT,
                                    ViewportType::VIEWPORT_INTERNAL);
    // Add an external viewport
    mFakePolicy->addDisplayViewport(tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, externalUniqueId, NO_PORT,
                                    ViewportType::VIEWPORT_EXTERNAL);
    // Add an virtual viewport
    mFakePolicy->addDisplayViewport(virtualDisplayId1,
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, virtualUniqueId1, NO_PORT,
                                    ViewportType::VIEWPORT_VIRTUAL);
    // Add another virtual viewport
    mFakePolicy->addDisplayViewport(virtualDisplayId2,
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                    DISPLAY_ORIENTATION_0, virtualUniqueId2, NO_PORT,
                                    ViewportType::VIEWPORT_VIRTUAL);
    // Check matching by type for internal
    internalViewport = mFakePolicy->getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);
    // Check matching by type for external
    std::optional<DisplayViewport> externalViewport =
            mFakePolicy->getDisplayViewportByType(ViewportType::VIEWPORT_EXTERNAL);
    // Check matching by uniqueId for virtual viewport #1
    std::optional<DisplayViewport> virtualViewport1 =
            mFakePolicy->getDisplayViewportByUniqueId(virtualUniqueId1);
    // Check matching by uniqueId for virtual viewport #2
    std::optional<DisplayViewport> virtualViewport2 =
            mFakePolicy->getDisplayViewportByUniqueId(virtualUniqueId2);

    // Viewports_TwoOfSameType
    const std::string uniqueId1 = tester.ConsumeRandomLengthString(50);
    const std::string uniqueId2 = tester.ConsumeRandomLengthString(50);
    int32_t displayId1 = tester.ConsumeIntegralInRange(0, 10);
    int32_t displayId2 = tester.ConsumeIntegralInRange(0, 10);
    std::vector<ViewportType> types = {ViewportType::VIEWPORT_INTERNAL,
                                       ViewportType::VIEWPORT_EXTERNAL,
                                       ViewportType::VIEWPORT_VIRTUAL};
    for (const ViewportType& type : types) {
        mFakePolicy->clearViewports();
        // Add a viewport
        mFakePolicy->addDisplayViewport(displayId1,
                                        tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                        tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                        DISPLAY_ORIENTATION_0, uniqueId1, NO_PORT, type);
        // Add another viewport
        mFakePolicy->addDisplayViewport(displayId2,
                                        tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                        tester.ConsumeIntegralInRange<int32_t>(0, kMaxRangeSize),
                                        DISPLAY_ORIENTATION_0, uniqueId2, NO_PORT, type);
        // Check that correct display viewport was returned by comparing the display IDs.
        std::optional<DisplayViewport> viewport1 =
                mFakePolicy->getDisplayViewportByUniqueId(uniqueId1);

        std::optional<DisplayViewport> viewport2 =
                mFakePolicy->getDisplayViewportByUniqueId(uniqueId2);

        // When there are multiple viewports of the same kind, and uniqueId is not specified
        // in the call to getDisplayViewport, then that situation is not supported.
        // The viewports can be stored in any order, so we cannot rely on the order, since that
        // is just implementation detail.
        // However, we can check that it still returns *a* viewport, we just cannot assert
        // which one specifically is returned.
        std::optional<DisplayViewport> someViewport = mFakePolicy->getDisplayViewportByType(type);
    }
    mFakePolicy.clear();

    return 0;
}

} // namespace android