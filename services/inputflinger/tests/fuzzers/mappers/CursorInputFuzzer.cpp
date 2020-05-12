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
#include "tests/fuzzers/commonHeaders/CursorMapperHelperClasses.h"
#include "tests/fuzzers/commonHeaders/InputReaderHelperClasses.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::unique_ptr<CursorInputMapperTest> cmt = std::make_unique<CursorInputMapperTest>();
    cmt->SetUp(&fdp);

    InputDevice* mDevice = cmt->GetmDevice();

    std::shared_ptr<FakePointerController> mFakePointerController =
            cmt->GetmFakePointerController();
    sp<FakeInputReaderPolicy> mFakePolicy = cmt->GetmFakePolicy();

    // WhenModeIsPointer_GetSources_ReturnsMouse
    CursorInputMapper* mapper = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "pointer");
    cmt->addMapperAndConfigure(mapper);

    // WhenModeIsNavigation_GetSources_ReturnsTrackball
    CursorInputMapper* mapper2 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mapper2);
    mapper2->getSources();

    // WhenModeIsPointer_PopulateDeviceInfo_ReturnsRangeFromPointerController
    CursorInputMapper* mapper3 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", fdp.ConsumeRandomLengthString(100).data());
    cmt->addMapperAndConfigure(mapper3);
    InputDeviceInfo info;
    mapper3->populateDeviceInfo(&info);
    // Initially there may not be a valid motion range.

    // When the bounds are set, then there should be a valid motion range.
    mFakePointerController->setBounds(fdp.ConsumeIntegralInRange(0, 100),
                                      fdp.ConsumeIntegralInRange(0, 100),
                                      fdp.ConsumeIntegralInRange(0, 799),
                                      fdp.ConsumeIntegralInRange(0, 479));
    InputDeviceInfo info2;
    mapper3->populateDeviceInfo(&info2);

    cmt->TearDown();

    return 0;
}

} // namespace android