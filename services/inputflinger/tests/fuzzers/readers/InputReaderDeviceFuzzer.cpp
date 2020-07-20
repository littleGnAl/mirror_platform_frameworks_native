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

static constexpr size_t kMaxSize = 100;

namespace android {

void addDevice(int32_t deviceId, const std::string& name, uint32_t classes,
               const PropertyMap* configuration, sp<FakeEventHub> mFakeEventHub,
               sp<InstrumentedInputReader> mReader) {
    mFakeEventHub->addDevice(deviceId, name, classes);
    if (configuration) {
        mFakeEventHub->addConfigurationMap(deviceId, configuration);
    }
    mFakeEventHub->finishDeviceScan();
    mReader->loopOnce();
    mReader->loopOnce();
    mFakeEventHub->assertQueueIsEmpty();
}
void configureDevice(uint32_t changes, InputDevice* device, sp<FakeInputReaderPolicy> mFakePolicy) {
    device->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(), changes);
}
void disableDevice(int32_t deviceId, InputDevice* device, sp<FakeInputReaderPolicy> mFakePolicy) {
    mFakePolicy->addDisabledDevice(deviceId);
    configureDevice(InputReaderConfiguration::CHANGE_ENABLED_STATE, device, mFakePolicy);
}
void enableDevice(int32_t deviceId, InputDevice* device, sp<FakeInputReaderPolicy> mFakePolicy) {
    mFakePolicy->removeDisabledDevice(deviceId);
    configureDevice(InputReaderConfiguration::CHANGE_ENABLED_STATE, device, mFakePolicy);
}
FakeInputMapper* addDeviceWithFakeInputMapper(int32_t deviceId, int32_t controllerNumber,
                                              const std::string& name, uint32_t classes,
                                              uint32_t sources, const PropertyMap* configuration,
                                              sp<FakeEventHub> mFakeEventHub,
                                              sp<InstrumentedInputReader> mReader) {
    InputDevice* device = mReader->newDevice(deviceId, controllerNumber, name, classes);
    FakeInputMapper* mapper = new FakeInputMapper(device, sources);
    device->addMapper(mapper);
    mReader->setNextDevice(device);
    addDevice(deviceId, name, classes, configuration, mFakeEventHub, mReader);
    return mapper;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    sp<TestInputListener> mFakeListener = new TestInputListener();
    sp<FakeInputReaderPolicy> mFakePolicy = new FakeInputReaderPolicy();
    sp<FakeEventHub> mFakeEventHub = new FakeEventHub();
    sp<InstrumentedInputReader> mReader =
            new InstrumentedInputReader(mFakeEventHub, mFakePolicy, mFakeListener);

    // GetInputDevices
    std::vector<InputDeviceInfo> inputDevices;
    mReader->getInputDevices(inputDevices);

    // Should also have received a notification describing the new input devices.
    inputDevices = mFakePolicy->getInputDevices();
    // WhenEnabledChanges_SendsDeviceResetNotification
    int32_t deviceId = fdp.ConsumeIntegralInRange(0, 10);
    constexpr uint32_t deviceClass = INPUT_DEVICE_CLASS_KEYBOARD;
    InputDevice* device =
            mReader->newDevice(deviceId, fdp.ConsumeIntegralInRange(0, 10) /*controllerNumber*/,
                               fdp.ConsumeRandomLengthString(
                                       fdp.ConsumeIntegralInRange<int32_t>(0, kMaxSize)),
                               deviceClass);

    // Must add at least one mapper or the device will be ignored!
    FakeInputMapper* mapper = new FakeInputMapper(device, AINPUT_SOURCE_KEYBOARD);
    device->addMapper(mapper);
    mReader->setNextDevice(device);
    addDevice(deviceId,
              fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<int32_t>(0, kMaxSize)),
              deviceClass, nullptr, mFakeEventHub, mReader);

    NotifyDeviceResetArgs resetArgs;

    disableDevice(deviceId, device, mFakePolicy);
    mReader->loopOnce();
    mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs);
    disableDevice(deviceId, device, mFakePolicy);
    mReader->loopOnce();

    mFakeListener->assertNotifyDeviceResetWasNotCalled();
    mFakeListener->assertNotifyConfigurationChangedWasNotCalled();

    enableDevice(deviceId, device, mFakePolicy);
    mReader->loopOnce();

    mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs);

    // GetKeyCodeState_ForwardsRequestsToMappers
    mapper->setKeyCodeState(fdp.ConsumeIntegralInRange<int32_t>(-5, 300), AKEY_STATE_DOWN);
    // GetScanCodeState_ForwardsRequestsToMappers

    mapper->setScanCodeState(fdp.ConsumeIntegralInRange<int32_t>(-5, 300), AKEY_STATE_DOWN);

    // GetSwitchState_ForwardsRequestsToMappers
    mapper->setSwitchState(SW_LID, AKEY_STATE_DOWN);

    // MarkSupportedKeyCodes_ForwardsRequestsToMappers
    mapper->addSupportedKeyCode(fdp.ConsumeIntegralInRange<int32_t>(-5, 300));
    mapper->addSupportedKeyCode(fdp.ConsumeIntegralInRange<int32_t>(-5, 300));

    // LoopOnce_WhenDeviceScanFinished_SendsConfigurationChanged
    addDevice(fdp.ConsumeIntegralInRange(0, 10), fdp.ConsumeRandomLengthString(kMaxSize),
              INPUT_DEVICE_CLASS_KEYBOARD, nullptr, mFakeEventHub, mReader);
    NotifyConfigurationChangedArgs args;

    // LoopOnce_ForwardsRawEventsToMappers
    mFakeEventHub->enqueueEvent(fdp.ConsumeIntegralInRange(0, 10),
                                fdp.ConsumeIntegralInRange(0, 10), EV_KEY, KEY_A,
                                fdp.ConsumeIntegralInRange(0, 10));
    mReader->loopOnce();

    // DeviceReset_IncrementsSequenceNumber
    // constexpr int32_t deviceId = 1;
    // constexpr uint32_t deviceClass = INPUT_DEVICE_CLASS_KEYBOARD;
    // InputDevice* device = mReader->newDevice(deviceId, 0 /*controllerNumber*/, "fake",
    // deviceClass);
    // Must add at least one mapper or the device will be ignored!
    mapper = new FakeInputMapper(device, AINPUT_SOURCE_KEYBOARD);
    device->addMapper(mapper);
    mReader->setNextDevice(device);

    addDevice(deviceId, fdp.ConsumeRandomLengthString(12), deviceClass, nullptr, mFakeEventHub,
              mReader);
    NotifyDeviceResetArgs resetArgs2;
    uint32_t prevSequenceNum = resetArgs2.sequenceNum;
    disableDevice(deviceId, device, mFakePolicy);
    mReader->loopOnce();
    mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs2);
    prevSequenceNum = resetArgs2.sequenceNum;
    enableDevice(deviceId, device, mFakePolicy);
    mReader->loopOnce();

    mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs2);
    prevSequenceNum = resetArgs2.sequenceNum;
    disableDevice(deviceId, device, mFakePolicy);
    mReader->loopOnce();
    mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs2);
    prevSequenceNum = resetArgs2.sequenceNum;

    // Device_CanDispatchToDisplay
    // constexpr int32_t deviceId = 1;
    // constexpr uint32_t deviceClass = INPUT_DEVICE_CLASS_KEYBOARD;
    std::string DEVICE_LOCATION = fdp.ConsumeRandomLengthString(kMaxSize);
    // InputDevice* device = mReader->newDevice(deviceId, 0 /*controllerNumber*/, "fake",
    // deviceClass, DEVICE_LOCATION);
    mapper = new FakeInputMapper(device, AINPUT_SOURCE_TOUCHSCREEN);
    device->addMapper(mapper);
    mReader->setNextDevice(device);

    addDevice(deviceId, fdp.ConsumeRandomLengthString(kMaxSize), deviceClass, nullptr,
              mFakeEventHub, mReader);
    uint8_t hdmi1 = fdp.ConsumeIntegralInRange(0, 10);
    // Associated touch screen with second display.
    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi1);
    // Add default and second display.
    std::string displayViewPortParam = "local" + fdp.ConsumeRandomLengthString(8) + ":" +
            fdp.ConsumeIntegralInRange<char>(0, kMaxSize);

    mFakePolicy->addDisplayViewport(DISPLAY_ID, fdp.ConsumeIntegralInRange<int32_t>(0, kMaxSize),
                                    fdp.ConsumeIntegralInRange<int32_t>(0, kMaxSize),
                                    DISPLAY_ORIENTATION_0, displayViewPortParam, NO_PORT,
                                    ViewportType::VIEWPORT_INTERNAL);
    mFakePolicy->addDisplayViewport(SECONDARY_DISPLAY_ID,
                                    fdp.ConsumeIntegralInRange<int32_t>(0, kMaxSize),
                                    fdp.ConsumeIntegralInRange<int32_t>(0, kMaxSize),
                                    DISPLAY_ORIENTATION_0,
                                    fdp.ConsumeRandomLengthString(8) + ":" +
                                            fdp.ConsumeIntegralInRange<char>(0, kMaxSize),
                                    hdmi1, ViewportType::VIEWPORT_EXTERNAL);
    mReader->requestRefreshConfiguration(InputReaderConfiguration::CHANGE_DISPLAY_INFO);
    mReader->loopOnce();
    // Check device.
    device->getId();
    mReader->canDispatchToDisplay(deviceId, DISPLAY_ID);

    return 0;
}

} // namespace android