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

#ifndef CURSORINPUTFUZZER_CURSORMAPPERHELPERCLASSES_H_
#define CURSORINPUTFUZZER_CURSORMAPPERHELPERCLASSES_H_

#include <string>
#include "mappers/include/InputReaderHelperClasses.h"

namespace android {

class InputMapperTest {
    // make testing easier
public:
    static const char *DEVICE_NAME;
    static const char *DEVICE_LOCATION;
    static const int32_t DEVICE_ID;
    static const int32_t DEVICE_GENERATION;
    static const int32_t DEVICE_CONTROLLER_NUMBER;
    static const uint32_t DEVICE_CLASSES;
    sp<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    sp<TestInputListener> mFakeListener;
    FakeInputReaderContext *mFakeContext;
    InputDevice *mDevice;
    virtual void SetUp() {
        mFakeEventHub = new FakeEventHub();
        mFakePolicy = new FakeInputReaderPolicy();
        mFakeListener = new TestInputListener();
        mFakeContext = new FakeInputReaderContext(mFakeEventHub, mFakePolicy, mFakeListener);
        InputDeviceIdentifier identifier;
        identifier.name = DEVICE_NAME;
        identifier.location = DEVICE_LOCATION;
        mDevice = new InputDevice(mFakeContext, DEVICE_ID, DEVICE_GENERATION,
                                  DEVICE_CONTROLLER_NUMBER, identifier, DEVICE_CLASSES);
        mFakeEventHub->addDevice(mDevice->getId(), DEVICE_NAME, 0);
    }
    virtual void TearDown() {
        delete mDevice;
        delete mFakeContext;
        mFakeListener.clear();
        mFakePolicy.clear();
        mFakeEventHub.clear();
    }
    virtual ~InputMapperTest() {}
    void addConfigurationProperty(const char *key, const char *value) {
        mFakeEventHub->addConfigurationProperty(mDevice->getId(), String8(key), String8(value));
    }
    void configureDevice(uint32_t changes) {
        mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(), changes);
    }
    void addMapperAndConfigure(InputMapper *mapper) {
        mDevice->addMapper(mapper);
        configureDevice(0);
        mDevice->reset(ARBITRARY_TIME);
    }
    void setDisplayInfoAndReconfigure(int32_t displayId, int32_t width, int32_t height,
                                      int32_t orientation, const std::string &uniqueId,
                                      std::optional<uint8_t> physicalPort,
                                      ViewportType viewportType) {
        mFakePolicy->addDisplayViewport(displayId, width, height, orientation, uniqueId,
                                        physicalPort, viewportType);
        configureDevice(InputReaderConfiguration::CHANGE_DISPLAY_INFO);
    }
    void clearViewports() { mFakePolicy->clearViewports(); }
    static void process(InputMapper *mapper, nsecs_t when, int32_t type, int32_t code,
                        int32_t value) {
        RawEvent event;
        event.when = when;
        event.deviceId = mapper->getDeviceId();
        event.type = type;
        event.code = code;
        event.value = value;
        mapper->process(&event);
    }
};
const char *InputMapperTest::DEVICE_NAME = "device";
const char *InputMapperTest::DEVICE_LOCATION = "USB1";
const int32_t InputMapperTest::DEVICE_ID = 1;
const int32_t InputMapperTest::DEVICE_GENERATION = 2;
const int32_t InputMapperTest::DEVICE_CONTROLLER_NUMBER = 0;
const uint32_t InputMapperTest::DEVICE_CLASSES = 0; // not needed for current tests

class CursorInputMapperTest : public InputMapperTest {
public:
    void prepareDisplay(int32_t orientation) {
        const std::string uniqueId = "local:0";
        const ViewportType viewportType = ViewportType::VIEWPORT_INTERNAL;
        setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation,
                                     uniqueId, NO_PORT, viewportType);
    }
    virtual void SetUp() {
        InputMapperTest::SetUp();
        mFakePointerController = new FakePointerController();
        mFakePolicy->setPointerController(mDevice->getId(), mFakePointerController);
    }

protected:
    static const int32_t TRACKBALL_MOVEMENT_THRESHOLD;
    sp<FakePointerController> mFakePointerController;
    void testMotionRotation(CursorInputMapper *mapper, int32_t originalX, int32_t originalY,
                            int32_t rotatedX, int32_t rotatedY);
};
const int32_t CursorInputMapperTest::TRACKBALL_MOVEMENT_THRESHOLD = 6;
void CursorInputMapperTest::testMotionRotation(CursorInputMapper *mapper, int32_t originalX,
                                               int32_t originalY, int32_t rotatedX,
                                               int32_t rotatedY) {
    NotifyMotionArgs args;
    process(mapper, ARBITRARY_TIME, EV_REL, REL_X, originalX);
    process(mapper, ARBITRARY_TIME, EV_REL, REL_Y, originalY);
    process(mapper, ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
}
} // namespace android

#endif // CURSORINPUTFUZZER_CURSORMAPPERHELPERCLASSES_H_
