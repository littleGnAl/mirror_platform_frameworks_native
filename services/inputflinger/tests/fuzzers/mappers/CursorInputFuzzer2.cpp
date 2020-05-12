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
    FuzzedDataProvider tester(data, size);

    std::unique_ptr<CursorInputMapperTest> cmt = std::make_unique<CursorInputMapperTest>();
    cmt->SetUp(&tester);

    InputDevice* mDevice = cmt->GetmDevice();
    FakeInputReaderContext* mFakeContext = cmt->GetmFakeContext();
    std::shared_ptr<FakePointerController> mFakePointerController =
            cmt->GetmFakePointerController();
    sp<FakeInputReaderPolicy> mFakePolicy = cmt->GetmFakePolicy();

    // Process_ShouldSetAllFieldsAndIncludeGlobalMetaState
    CursorInputMapper* mapper = new CursorInputMapper(mDevice);

    cmt->addConfigurationProperty("cursor.mode", "navigation");

    cmt->addMapperAndConfigure(mapper);

    mFakeContext->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);
    // Button press.
    // Mostly testing non x/y behavior here so we don't need to check again elsewhere.
    cmt->process(mapper, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33),
                 tester.ConsumeIntegralInRange(-1, 0x181), tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33),
                 tester.ConsumeIntegralInRange(-1, 0x181), tester.ConsumeIntegralInRange(-1, 3));

    // Process_ShouldHandleIndependentButtonUpdates
    CursorInputMapper* mapper3 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mapper3);
    // Button press.
    cmt->process(mapper3, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), BTN_MOUSE,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper3, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));
    // Button release.
    cmt->process(mapper3, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), BTN_MOUSE,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper3, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    // Process_WhenNotOrientationAware_ShouldNotRotateMotions
    CursorInputMapper* mapper5 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mapper5);
    cmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));

    // Process_WhenOrientationAware_ShouldRotateMotions
    CursorInputMapper* mapper6 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addConfigurationProperty("cursor.orientationAware", "1");
    cmt->addMapperAndConfigure(mapper6);
    cmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));

    // Process_ShouldHandleAllButtons
    CursorInputMapper* mapper7 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "pointer");
    cmt->addMapperAndConfigure(mapper7);

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
    cmt->process(mapper7, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper7, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    cmt->process(mapper7, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper7, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    mFakePolicy->setPointerCapture(false);
    cmt->configureDevice(InputReaderConfiguration::CHANGE_POINTER_CAPTURE);

    cmt->process(mapper7, ARBITRARY_TIME, EV_REL, REL_X, 10);
    cmt->process(mapper7, ARBITRARY_TIME, EV_REL, REL_Y, 20);
    cmt->process(mapper7, ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);

    // Process_ShouldHandleDisplayId
    CursorInputMapper* mapper10 = new CursorInputMapper(mDevice);
    cmt->addMapperAndConfigure(mapper10);
    // Setup PointerController for second display.
    constexpr int32_t SECOND_DISPLAY_ID = 1;
    mFakePointerController->setBounds(tester.ConsumeIntegralInRange(-25, 100),
                                      tester.ConsumeIntegralInRange(-25, 100),
                                      tester.ConsumeIntegralInRange(0, 800),
                                      tester.ConsumeIntegralInRange(0, 500));
    mFakePointerController->setPosition(tester.ConsumeIntegralInRange(-1, 101),
                                        tester.ConsumeIntegralInRange(-2, 200));
    mFakePointerController->setButtonState(tester.ConsumeIntegralInRange(-1, 101));
    DisplayViewport viewport;
    viewport.displayId = SECOND_DISPLAY_ID;
    mFakePointerController->setDisplayViewport(viewport);
    // NotifyMotionArgs args;
    cmt->process(mapper10, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), REL_X,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper10, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), REL_Y,
                 tester.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper10, ARBITRARY_TIME, tester.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 tester.ConsumeIntegralInRange(-1, 3));

    cmt->TearDown();

    return 0;
}

} // namespace android