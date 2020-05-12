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
#include "include/fuzzTestInputListener.h"
#include "inputMapperFuzzers/include/cursorMapperHelperClasses.h"
#include "inputMapperFuzzers/include/inputReaderHelperClasses.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider tester(data, size);

    const std::string UNIQUE_ID = tester.ConsumeRandomLengthString(50) + ":" +
            static_cast<char>(tester.ConsumeIntegralInRange(0, 10));
    const std::string DEVICE_NAME = tester.ConsumeRandomLengthString(16);
    const std::string DEVICE_LOCATION = tester.ConsumeRandomLengthString(12);
    const int32_t DEVICE_ID = tester.ConsumeIntegralInRange<int>(0, 5);
    const int32_t DEVICE_GENERATION = tester.ConsumeIntegralInRange<int>(0, 5);
    const int32_t DEVICE_CONTROLLER_NUMBER = tester.ConsumeIntegralInRange<int>(0, 5);
    const uint32_t DEVICE_CLASSES = tester.ConsumeIntegralInRange<int>(0, 5);
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

    CursorInputMapper *mappers[6];

    // Process_ShouldSetAllFieldsAndIncludeGlobalMetaState
    mappers[0] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mappers[0]);
    mFakeContext->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    // Button press.
    // Mostly testing non x/y behavior here so we don't need to check again
    // elsewhere.
    cmt->process(mappers[0], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33),
                 tester.ConsumeIntegralInRange(-1, 0x181), tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[0], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33),
                 tester.ConsumeIntegralInRange(-1, 0x181), tester.ConsumeIntegralInRange(-1, 3));

    // Process_ShouldHandleIndependentButtonUpdates
    mappers[1] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mappers[1]);

    // Button press.
    cmt->process(mappers[1], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), BTN_MOUSE,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[1], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    // Button release.
    cmt->process(mappers[1], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), BTN_MOUSE,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[1], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    // Process_WhenNotOrientationAware_ShouldNotRotateMotions
    mappers[2] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mappers[2]);
    cmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));

    // Process_WhenOrientationAware_ShouldRotateMotions
    mappers[3] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addConfigurationProperty("cursor.orientationAware", "1");
    cmt->addMapperAndConfigure(mappers[3]);
    cmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));

    // Process_ShouldHandleAllButtons
    mappers[4] = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "pointer");
    cmt->addMapperAndConfigure(mappers[4]);
    mFakePointerController->setBounds(tester.ConsumeIntegralInRange(-25, 100),
                                      tester.ConsumeIntegralInRange(-25, 100),
                                      tester.ConsumeIntegralInRange(0, 800),
                                      tester.ConsumeIntegralInRange(0, 500));
    mFakePointerController->setPosition(tester.ConsumeIntegralInRange(-1, 101),
                                        tester.ConsumeIntegralInRange(-2, 200));
    mFakePointerController->setButtonState(tester.ConsumeIntegralInRange(-1, 101));
    // NotifyMotionArgs motionArgs;
    // NotifyKeyArgs keyArgs;
    // press BTN_LEFT, release BTN_LEFT
    cmt->process(mappers[4], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[4], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    cmt->process(mappers[4], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[4], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    mFakePolicy->setPointerCapture(false);
    cmt->configureDevice(InputReaderConfiguration::CHANGE_POINTER_CAPTURE);

    cmt->process(mappers[4], ARBITRARY_TIME, EV_REL, REL_X, 10);
    cmt->process(mappers[4], ARBITRARY_TIME, EV_REL, REL_Y, 20);
    cmt->process(mappers[4], ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);

    // Process_ShouldHandleDisplayId
    mappers[5] = new CursorInputMapper(mDevice);
    cmt->addMapperAndConfigure(mappers[5]);
    // Setup PointerController for second display.
    constexpr int32_t SECOND_DISPLAY_ID = 1;
    mFakePointerController->setBounds(tester.ConsumeIntegralInRange(-25, 100),
                                      tester.ConsumeIntegralInRange(-25, 100),
                                      tester.ConsumeIntegralInRange(0, 800),
                                      tester.ConsumeIntegralInRange(0, 500));
    mFakePointerController->setPosition(tester.ConsumeIntegralInRange(-1, 101),
                                        tester.ConsumeIntegralInRange(-2, 200));
    mFakePointerController->setButtonState(tester.ConsumeIntegralInRange(-1, 101));
    mFakePointerController->setDisplayId(SECOND_DISPLAY_ID);
    // NotifyMotionArgs args;
    cmt->process(mappers[5], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), REL_X,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[5], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), REL_Y,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mappers[5], ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    // Clear out our created objects
    cmt->TearDown();
    delete cmt;
    delete mDevice;
    delete mFakeContext;

    return 0;
}

} // namespace android
