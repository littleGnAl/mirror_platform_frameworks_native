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
#include "mappers/include/InputReaderHelperClasses.h"
#include "mappers/include/KeyboardMapperHelperClasses.h"

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

    InputMapperTest *imt = new InputMapperTest();
    imt->SetUp();
    KeyboardInputMapperTest *kmt = new KeyboardInputMapperTest();
    kmt->SetUp();

    // GetSources
    KeyboardInputMapper *mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                                          AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);
    mapper->getSources();

    // Process_SimpleKeyPress
    const int32_t USAGE_A = 0x070004;
    const int32_t USAGE_UNKNOWN = 0x07ffff;
    mFakeEventHub->addKey(DEVICE_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(DEVICE_ID, 0, USAGE_A, AKEYCODE_A, POLICY_FLAG_WAKE);
    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);

    // Simulate some keys up/down
    for (int i = 0; i < tester.ConsumeIntegralInRange(0, 100); i++) {
        InputMapperTest::process(mapper, ARBITRARY_TIME, EV_MSC,
                                 tester.ConsumeIntegralInRange(-1, 9),
                                 tester.ConsumeBool() ? USAGE_A : USAGE_UNKNOWN);
        InputMapperTest::process(mapper, ARBITRARY_TIME + tester.ConsumeIntegralInRange(0, 50),
                                 EV_KEY, tester.ConsumeBool() ? 0 : KEY_UNKNOWN,
                                 tester.ConsumeIntegralInRange(0, 1));
    }

    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addConfigurationProperty("keyboard.orientationAware", "1");
    imt->addMapperAndConfigure(mapper);
    kmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));
    imt->clearViewports();
    kmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));

    // Special case: if orientation changes while key is down, we still emit the
    // same keycode in the key up as we did in the key down.

    imt->clearViewports();
    kmt->prepareDisplay(DISPLAY_ORIENTATION_270);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, KEY_UP, 1);

    imt->clearViewports();
    kmt->prepareDisplay(DISPLAY_ORIENTATION_180);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, KEY_UP, 0);

    // DisplayIdConfigurationChange_OrientationAware
    // If the keyboard is orientation aware,
    // key events should be associated with the internal viewport
    mFakeEventHub->addKey(DEVICE_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);
    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addConfigurationProperty("keyboard.orientationAware", "1");
    imt->addMapperAndConfigure(mapper);

    // GetScanCodeState
    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);
    mFakeEventHub->setScanCodeState(DEVICE_ID, tester.ConsumeIntegralInRange(-1, 289),
                                    tester.ConsumeBool());

    // MarkSupportedKeyCodes
    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);
    mFakeEventHub->addKey(DEVICE_ID, tester.ConsumeIntegralInRange(-1, 289), 0,
                          tester.ConsumeIntegralInRange(-1, 289), 0);

    // Process_LockedKeysShouldToggleMetaStateAndLeds
    mFakeEventHub->addLed(DEVICE_ID, tester.ConsumeIntegralInRange(-1, 17), tester.ConsumeBool());
    mFakeEventHub->addKey(DEVICE_ID, tester.ConsumeIntegralInRange(-1, 465), 0,
                          tester.ConsumeIntegralInRange(-1, 289), 0);

    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);
    // Initialization should have turned all of the lights off.
    // Toggle caps lock on.
    int keyToPressAndRelease = tester.ConsumeIntegralInRange(-1, 465);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, keyToPressAndRelease, 1);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, keyToPressAndRelease, 0);
    // Toggle num lock on.

    // Clear out our created objects
    kmt->TearDown();
    delete kmt;
    imt->TearDown();
    delete imt;
    delete mDevice;
    delete mFakeContext;

    return 0;
}

} // namespace android
