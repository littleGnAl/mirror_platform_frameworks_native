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
#include "tests/fuzzers/commonHeaders/InputReaderHelperClasses.h"
#include "tests/fuzzers/commonHeaders/KeyboardMapperHelperClasses.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    const int32_t DEVICE_ID = fdp.ConsumeIntegralInRange<int32_t>(0, 5);

    std::unique_ptr<InputMapperTest> imt = std::make_unique<InputMapperTest>();
    imt->SetUp(&fdp);
    InputDevice* mDevice = imt->GetmDevice();
    sp<FakeInputReaderPolicy> mFakePolicy = imt->GetmFakePolicy();
    sp<FakeEventHub> mFakeEventHub = imt->GetmFakeEventHub();

    // GetSources
    KeyboardInputMapper* mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
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
    // Key down by usage code.
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_MSC, fdp.ConsumeIntegralInRange(-1, 9),
                             USAGE_A);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, 0, 1);

    // Key up by usage code.
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_MSC, fdp.ConsumeIntegralInRange(-1, 9),
                             USAGE_A);
    InputMapperTest::process(mapper, ARBITRARY_TIME + 1, EV_KEY, 0, 0);

    // Key down with unknown scan code or usage code.
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_MSC, fdp.ConsumeIntegralInRange(-1, 9),
                             USAGE_UNKNOWN);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, KEY_UNKNOWN, 1);

    // Key up with unknown scan code or usage code.
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_MSC, fdp.ConsumeIntegralInRange(-1, 9),
                             USAGE_UNKNOWN);
    InputMapperTest::process(mapper, ARBITRARY_TIME + 1, EV_KEY, KEY_UNKNOWN, 0);

    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addConfigurationProperty("keyboard.orientationAware", "1");
    imt->addMapperAndConfigure(mapper);

    imt->clearViewports();
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, KEY_UP, 1);

    imt->clearViewports();
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
    mFakeEventHub->setScanCodeState(DEVICE_ID, fdp.ConsumeIntegralInRange(-1, 289),
                                    fdp.ConsumeBool());

    // MarkSupportedKeyCodes
    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);
    mFakeEventHub->addKey(DEVICE_ID, fdp.ConsumeIntegralInRange(-1, 289), 0,
                          fdp.ConsumeIntegralInRange(-1, 289), 0);

    // Process_LockedKeysShouldToggleMetaStateAndLeds
    mFakeEventHub->addLed(DEVICE_ID, fdp.ConsumeIntegralInRange(-1, 17), fdp.ConsumeBool());
    mFakeEventHub->addKey(DEVICE_ID, fdp.ConsumeIntegralInRange(-1, 465), 0,
                          fdp.ConsumeIntegralInRange(-1, 289), 0);

    mapper = new KeyboardInputMapper(mDevice, AINPUT_SOURCE_KEYBOARD,
                                     AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    imt->addMapperAndConfigure(mapper);
    // Initialization should have turned all of the lights off.
    // Toggle caps lock on.
    int32_t keyToPressAndRelease = fdp.ConsumeIntegralInRange<int32_t>(-1, 465);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, keyToPressAndRelease, 1);
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, keyToPressAndRelease, 0);
    // Toggle num lock on.

    imt->TearDown();

    return 0;
}

} // namespace android