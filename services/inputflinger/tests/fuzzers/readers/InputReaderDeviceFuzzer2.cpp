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
#include "tests/fuzzers/TestInputListenerLibrary/TestInputListener.h"
#include "tests/fuzzers/commonHeaders/InputReaderHelperClasses.h"

namespace android {

void addDevice(int32_t deviceId, const std::string &name, uint32_t classes,
               const PropertyMap *configuration, std::shared_ptr<FakeEventHub> mFakeEventHub,
               std::shared_ptr<InstrumentedInputReader> mReader) {
    mFakeEventHub->addDevice(deviceId, name, classes);
    if (configuration) {
        mFakeEventHub->addConfigurationMap(deviceId, configuration);
    }
    mFakeEventHub->finishDeviceScan();
    mReader->loopOnce();
    mReader->loopOnce();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    const int32_t DEVICE_ID = fdp.ConsumeIntegralInRange<int32_t>(0, 5);
    const int32_t DEVICE_GENERATION = fdp.ConsumeIntegralInRange<int32_t>(0, 5);
    const int32_t DEVICE_CONTROLLER_NUMBER = fdp.ConsumeIntegralInRange<int32_t>(0, 5);
    const uint32_t DEVICE_CLASSES =
            INPUT_DEVICE_CLASS_KEYBOARD | INPUT_DEVICE_CLASS_TOUCH | INPUT_DEVICE_CLASS_JOYSTICK;
    InputDeviceIdentifier identifier;

    sp<TestInputListener> mFakeListener = new TestInputListener();
    sp<FakeInputReaderPolicy> mFakePolicy = new FakeInputReaderPolicy();
    sp<FakeEventHub> mFakeEventHub = new FakeEventHub();
    std::shared_ptr<InstrumentedInputReader> mReader =
            std::make_shared<InstrumentedInputReader>(mFakeEventHub, mFakePolicy, mFakeListener);
    std::unique_ptr<FakeInputReaderContext> mFakeContext =
            std::make_unique<FakeInputReaderContext>(mFakeEventHub, mFakePolicy, mFakeListener);
    std::unique_ptr<InputDevice> mDevice =
            std::make_unique<InputDevice>(mFakeContext.get(), DEVICE_ID, DEVICE_GENERATION,
                                          DEVICE_CONTROLLER_NUMBER, identifier, DEVICE_CLASSES);

    // WhenNoMappersAreRegistered_DeviceIsIgnored
    InputReaderConfiguration config;
    mDevice->configure(ARBITRARY_TIME, &config, 0);
    // Reset.
    mDevice->reset(ARBITRARY_TIME);
    NotifyDeviceResetArgs resetArgs;

    // Metadata.
    mDevice->getSources();
    InputDeviceInfo info;
    mDevice->getDeviceInfo(&info);

    // State queries.
    mDevice->getMetaState();

    // WhenMappersAreRegistered_DeviceIsNotIgnoredAndForwardsRequestsToMappers
    std::vector<char> key = fdp.ConsumeBytesWithTerminator<char>(8);   // 8 due to original test
    std::vector<char> value = fdp.ConsumeBytesWithTerminator<char>(8); // 8 due to original test
    mFakeEventHub->addConfigurationProperty(DEVICE_ID, String8(key.data()), String8(value.data()));
    FakeInputMapper *mapper1 = new FakeInputMapper(mDevice.get(), AINPUT_SOURCE_KEYBOARD);
    mapper1->setKeyboardType(AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    mapper1->setMetaState(AMETA_ALT_ON);
    mapper1->addSupportedKeyCode(fdp.ConsumeIntegralInRange<int32_t>(-3, 300));
    mapper1->setKeyCodeState(fdp.ConsumeIntegralInRange<int32_t>(-3, 300),
                             fdp.ConsumeIntegralInRange<int32_t>(-2, 3));
    mapper1->setScanCodeState(fdp.ConsumeIntegralInRange(0, 10),
                              fdp.ConsumeIntegralInRange<int32_t>(-2, 3));
    mapper1->setScanCodeState(fdp.ConsumeIntegralInRange(0, 10),
                              fdp.ConsumeIntegralInRange<int32_t>(-2, 3));
    mapper1->setSwitchState(fdp.ConsumeIntegralInRange(0, 10),
                            fdp.ConsumeIntegralInRange<int32_t>(-2, 3));
    mDevice->addMapper(mapper1);

    FakeInputMapper *mapper2 = new FakeInputMapper(mDevice.get(), AINPUT_SOURCE_TOUCHSCREEN);
    mapper2->setMetaState(AMETA_SHIFT_ON);
    mDevice->addMapper(mapper2);
    // InputReaderConfiguration config;
    mDevice->configure(ARBITRARY_TIME, &config, fdp.ConsumeIntegralInRange(0, 10));
    String8 propertyValue;

    // Reset
    mDevice->reset(ARBITRARY_TIME);

    // Metadata.
    mDevice->isIgnored();
    // InputDeviceInfo info;
    mDevice->getDeviceInfo(&info);

    // Event handling.
    RawEvent event;
    mDevice->process(&event, 1);

    mDevice.reset();
    mFakeContext.reset();
    mReader.reset();
    mFakeEventHub.clear();
    mFakePolicy.clear();
    mFakeListener.clear();
    return 0;
}

} // namespace android
