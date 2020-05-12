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
#include "include/TestInputListener.h"
#include "mappers/include/CursorMapperHelperClasses.h"
#include "mappers/include/InputReaderHelperClasses.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider tester(data, size);

    const std::string UNIQUE_ID = tester.ConsumeRandomLengthString(50) + ":" +
            static_cast<char>(tester.ConsumeIntegralInRange(0, 10));
    const std::string DEVICE_NAME = tester.ConsumeRandomLengthString(16);
    const std::string DEVICE_LOCATION = tester.ConsumeRandomLengthString(12);
    const int32_t DEVICE_ID = tester.ConsumeIntegralInRange<int32_t>(0, 5);
    const int32_t DEVICE_GENERATION = tester.ConsumeIntegralInRange<int32_t>(0, 5);
    const int32_t DEVICE_CONTROLLER_NUMBER = tester.ConsumeIntegralInRange<int32_t>(0, 5);
    const uint32_t DEVICE_CLASSES = tester.ConsumeIntegralInRange<uint32_t>(0, 5);
    sp<FakeEventHub> mFakeEventHub = new FakeEventHub();
    sp<FakeInputReaderPolicy> mFakePolicy = new FakeInputReaderPolicy();
    sp<TestInputListener> mFakeListener = new TestInputListener();
    FakeInputReaderContext *mFakeContext =
            new FakeInputReaderContext(mFakeEventHub, mFakePolicy, mFakeListener);
    InputDeviceIdentifier identifier;
    identifier.name = DEVICE_NAME;
    identifier.location = DEVICE_LOCATION;

    InputDevice *mDevice = new InputDevice(mFakeContext, DEVICE_ID, DEVICE_GENERATION,
                                           DEVICE_CONTROLLER_NUMBER, identifier, DEVICE_CLASSES);

    sp<FakePointerController> mFakePointerController = new FakePointerController();
    mFakePolicy->setPointerController(mDevice->getId(), mFakePointerController);

    CursorInputMapperTest *cmt = new CursorInputMapperTest();
    cmt->SetUp();

    CursorInputMapper *mappers[3];

    // WhenModeIsPointer_GetSources_ReturnsMouse
    mappers[0] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "pointer");
    cmt->addMapperAndConfigure(mappers[0]);

    // WhenModeIsNavigation_GetSources_ReturnsTrackball
    mappers[1] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mappers[1]);
    mappers[1]->getSources();

    // WhenModeIsPointer_PopulateDeviceInfo_ReturnsRangeFromPointerController
    mappers[2] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", tester.ConsumeRandomLengthString(100).data());
    cmt->addMapperAndConfigure(mappers[2]);
    InputDeviceInfo info;
    mappers[2]->populateDeviceInfo(&info);
    // Initially there may not be a valid motion range.

    // When the bounds are set, then there should be a valid motion range.
    mFakePointerController->setBounds(tester.ConsumeIntegralInRange(0, 100),
                                      tester.ConsumeIntegralInRange(0, 100),
                                      tester.ConsumeIntegralInRange(0, 799),
                                      tester.ConsumeIntegralInRange(0, 479));
    InputDeviceInfo info2;
    mappers[2]->populateDeviceInfo(&info2);

    // Clear out our created objects
    cmt->TearDown();
    delete cmt;
    delete mDevice;
    delete mFakeContext;

    return 0;
}

} // namespace android
