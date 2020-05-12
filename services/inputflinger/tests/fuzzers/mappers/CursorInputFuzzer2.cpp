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
    cmt->process(mapper, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33),
                 fdp.ConsumeIntegralInRange(-1, 0x181), fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33),
                 fdp.ConsumeIntegralInRange(-1, 0x181), fdp.ConsumeIntegralInRange(-1, 3));

    // Process_ShouldHandleIndependentButtonUpdates
    CursorInputMapper* mapper3 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mapper3);
    // Button press.
    cmt->process(mapper3, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), BTN_MOUSE,
                 fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper3, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));
    // Button release.
    cmt->process(mapper3, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), BTN_MOUSE,
                 fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper3, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));

    // Process_WhenNotOrientationAware_ShouldNotRotateMotions
    CursorInputMapper* mapper5 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addMapperAndConfigure(mapper5);
    cmt->prepareDisplay(fdp.ConsumeIntegralInRange(-1, 4));

    // Process_WhenOrientationAware_ShouldRotateMotions
    CursorInputMapper* mapper6 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "navigation");
    cmt->addConfigurationProperty("cursor.orientationAware", "1");
    cmt->addMapperAndConfigure(mapper6);
    cmt->prepareDisplay(fdp.ConsumeIntegralInRange(-1, 4));

    // Process_ShouldHandleAllButtons
    CursorInputMapper* mapper7 = new CursorInputMapper(mDevice);
    cmt->addConfigurationProperty("cursor.mode", "pointer");
    cmt->addMapperAndConfigure(mapper7);

    mFakePointerController->setBounds(fdp.ConsumeIntegralInRange(-25, 100),
                                      fdp.ConsumeIntegralInRange(-25, 100),
                                      fdp.ConsumeIntegralInRange(0, 800),
                                      fdp.ConsumeIntegralInRange(0, 500));
    mFakePointerController->setPosition(fdp.ConsumeIntegralInRange(-1, 101),
                                        fdp.ConsumeIntegralInRange(-2, 200));
    mFakePointerController->setButtonState(fdp.ConsumeIntegralInRange(-1, 101));
    // NotifyMotionArgs motionArgs;
    // NotifyKeyArgs keyArgs;
    // press BTN_LEFT, release BTN_LEFT
    cmt->process(mapper7, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper7, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));

    cmt->process(mapper7, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper7, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));

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
    mFakePointerController->setBounds(fdp.ConsumeIntegralInRange(-25, 100),
                                      fdp.ConsumeIntegralInRange(-25, 100),
                                      fdp.ConsumeIntegralInRange(0, 800),
                                      fdp.ConsumeIntegralInRange(0, 500));
    mFakePointerController->setPosition(fdp.ConsumeIntegralInRange(-1, 101),
                                        fdp.ConsumeIntegralInRange(-2, 200));
    mFakePointerController->setButtonState(fdp.ConsumeIntegralInRange(-1, 101));
    DisplayViewport viewport;
    viewport.displayId = SECOND_DISPLAY_ID;
    mFakePointerController->setDisplayViewport(viewport);
    // NotifyMotionArgs args;
    cmt->process(mapper10, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), REL_X,
                 fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper10, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), REL_Y,
                 fdp.ConsumeIntegralInRange(-1, 3));
    cmt->process(mapper10, ARBITRARY_TIME, fdp.ConsumeIntegralInRange(-1, 33), SYN_REPORT,
                 fdp.ConsumeIntegralInRange(-1, 3));

    cmt->TearDown();

    return 0;
}

} // namespace android