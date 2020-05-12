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

#ifndef MULTITOUCHINPUTFUZZER_MULTITOUCHINPUTHELPERCLASSES_H_
#define MULTITOUCHINPUTFUZZER_MULTITOUCHINPUTHELPERCLASSES_H_

#include <string>

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

class TouchInputMapperTest : public InputMapperTest {
public:
    static const int32_t RAW_X_MIN;
    static const int32_t RAW_X_MAX;
    static const int32_t RAW_Y_MIN;
    static const int32_t RAW_Y_MAX;
    static const int32_t RAW_TOUCH_MIN;
    static const int32_t RAW_TOUCH_MAX;
    static const int32_t RAW_TOOL_MIN;
    static const int32_t RAW_TOOL_MAX;
    static const int32_t RAW_PRESSURE_MIN;
    static const int32_t RAW_PRESSURE_MAX;
    static const int32_t RAW_ORIENTATION_MIN;
    static const int32_t RAW_ORIENTATION_MAX;
    static const int32_t RAW_DISTANCE_MIN;
    static const int32_t RAW_DISTANCE_MAX;
    static const int32_t RAW_TILT_MIN;
    static const int32_t RAW_TILT_MAX;
    static const int32_t RAW_ID_MIN;
    static const int32_t RAW_ID_MAX;
    static const int32_t RAW_SLOT_MIN;
    static const int32_t RAW_SLOT_MAX;
    static const float X_PRECISION;
    static const float Y_PRECISION;
    static const float X_PRECISION_VIRTUAL;
    static const float Y_PRECISION_VIRTUAL;
    static const float GEOMETRIC_SCALE;
    static const TouchAffineTransformation AFFINE_TRANSFORM;
    static const VirtualKeyDefinition VIRTUAL_KEYS[2];
    const std::string UNIQUE_ID = "local:0";
    const std::string SECONDARY_UNIQUE_ID = "local:1";
    enum Axes {
        POSITION = 1 << 0,
        TOUCH = 1 << 1,
        TOOL = 1 << 2,
        PRESSURE = 1 << 3,
        ORIENTATION = 1 << 4,
        MINOR = 1 << 5,
        ID = 1 << 6,
        DISTANCE = 1 << 7,
        TILT = 1 << 8,
        SLOT = 1 << 9,
        TOOL_TYPE = 1 << 10,
    };
    void prepareDisplay(int32_t orientation, std::optional<uint8_t> port = NO_PORT);
    void prepareSecondaryDisplay(ViewportType type, std::optional<uint8_t> port = NO_PORT);
    void prepareVirtualDisplay(int32_t orientation);
    void prepareVirtualKeys();
    void prepareLocationCalibration();
    int32_t toRawX(float displayX);
    int32_t toRawY(float displayY);
    float toCookedX(float rawX, float rawY);
    float toCookedY(float rawX, float rawY);
    float toDisplayX(int32_t rawX);
    float toDisplayX(int32_t rawX, int32_t displayWidth);
    float toDisplayY(int32_t rawY);
    float toDisplayY(int32_t rawY, int32_t displayHeight);
};
const int32_t TouchInputMapperTest::RAW_X_MIN = 25;
const int32_t TouchInputMapperTest::RAW_X_MAX = 1019;
const int32_t TouchInputMapperTest::RAW_Y_MIN = 30;
const int32_t TouchInputMapperTest::RAW_Y_MAX = 1009;
const int32_t TouchInputMapperTest::RAW_TOUCH_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TOUCH_MAX = 31;
const int32_t TouchInputMapperTest::RAW_TOOL_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TOOL_MAX = 15;
const int32_t TouchInputMapperTest::RAW_PRESSURE_MIN = 0;
const int32_t TouchInputMapperTest::RAW_PRESSURE_MAX = 255;
const int32_t TouchInputMapperTest::RAW_ORIENTATION_MIN = -7;
const int32_t TouchInputMapperTest::RAW_ORIENTATION_MAX = 7;
const int32_t TouchInputMapperTest::RAW_DISTANCE_MIN = 0;
const int32_t TouchInputMapperTest::RAW_DISTANCE_MAX = 7;
const int32_t TouchInputMapperTest::RAW_TILT_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TILT_MAX = 150;
const int32_t TouchInputMapperTest::RAW_ID_MIN = 0;
const int32_t TouchInputMapperTest::RAW_ID_MAX = 9;
const int32_t TouchInputMapperTest::RAW_SLOT_MIN = 0;
const int32_t TouchInputMapperTest::RAW_SLOT_MAX = 9;
const float TouchInputMapperTest::X_PRECISION =
        static_cast<float>(RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_WIDTH;
const float TouchInputMapperTest::Y_PRECISION =
        static_cast<float>(RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_HEIGHT;
const float TouchInputMapperTest::X_PRECISION_VIRTUAL =
        static_cast<float>(RAW_X_MAX - RAW_X_MIN + 1) / VIRTUAL_DISPLAY_WIDTH;
const float TouchInputMapperTest::Y_PRECISION_VIRTUAL =
        static_cast<float>(RAW_Y_MAX - RAW_Y_MIN + 1) / VIRTUAL_DISPLAY_HEIGHT;
const TouchAffineTransformation TouchInputMapperTest::AFFINE_TRANSFORM =
        TouchAffineTransformation(1, -2, 3, -4, 5, -6);
const float TouchInputMapperTest::GEOMETRIC_SCALE =
        avg(static_cast<float>(DISPLAY_WIDTH) / (RAW_X_MAX - RAW_X_MIN + 1),
            static_cast<float>(DISPLAY_HEIGHT) / (RAW_Y_MAX - RAW_Y_MIN + 1));
const VirtualKeyDefinition TouchInputMapperTest::VIRTUAL_KEYS[2] = {
        {KEY_HOME, 60, DISPLAY_HEIGHT + 15, 20, 20},
        {KEY_MENU, DISPLAY_HEIGHT - 60, DISPLAY_WIDTH + 15, 20, 20},
};
void TouchInputMapperTest::prepareDisplay(int32_t orientation, std::optional<uint8_t> port) {
    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation, UNIQUE_ID,
                                 port, ViewportType::VIEWPORT_INTERNAL);
}
void TouchInputMapperTest::prepareSecondaryDisplay(ViewportType type, std::optional<uint8_t> port) {
    setDisplayInfoAndReconfigure(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                 DISPLAY_ORIENTATION_0, SECONDARY_UNIQUE_ID, port, type);
}
void TouchInputMapperTest::prepareVirtualDisplay(int32_t orientation) {
    setDisplayInfoAndReconfigure(VIRTUAL_DISPLAY_ID, VIRTUAL_DISPLAY_WIDTH, VIRTUAL_DISPLAY_HEIGHT,
                                 orientation, VIRTUAL_DISPLAY_UNIQUE_ID, NO_PORT,
                                 ViewportType::VIEWPORT_VIRTUAL);
}
void TouchInputMapperTest::prepareVirtualKeys() {
    mFakeEventHub->addVirtualKeyDefinition(DEVICE_ID, VIRTUAL_KEYS[0]);
    mFakeEventHub->addVirtualKeyDefinition(DEVICE_ID, VIRTUAL_KEYS[1]);
    mFakeEventHub->addKey(DEVICE_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(DEVICE_ID, KEY_MENU, 0, AKEYCODE_MENU, POLICY_FLAG_WAKE);
}
void TouchInputMapperTest::prepareLocationCalibration() {
    mFakePolicy->setTouchAffineTransformation(AFFINE_TRANSFORM);
}
int32_t TouchInputMapperTest::toRawX(float displayX) {
    return int32_t(displayX * (RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_WIDTH + RAW_X_MIN);
}
int32_t TouchInputMapperTest::toRawY(float displayY) {
    return int32_t(displayY * (RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_HEIGHT + RAW_Y_MIN);
}
float TouchInputMapperTest::toCookedX(float rawX, float rawY) {
    AFFINE_TRANSFORM.applyTo(rawX, rawY);
    return rawX;
}
float TouchInputMapperTest::toCookedY(float rawX, float rawY) {
    AFFINE_TRANSFORM.applyTo(rawX, rawY);
    return rawY;
}
float TouchInputMapperTest::toDisplayX(int32_t rawX) {
    return toDisplayX(rawX, DISPLAY_WIDTH);
}
float TouchInputMapperTest::toDisplayX(int32_t rawX, int32_t displayWidth) {
    return static_cast<float>(rawX - RAW_X_MIN) * displayWidth / (RAW_X_MAX - RAW_X_MIN + 1);
}
float TouchInputMapperTest::toDisplayY(int32_t rawY) {
    return toDisplayY(rawY, DISPLAY_HEIGHT);
}
float TouchInputMapperTest::toDisplayY(int32_t rawY, int32_t displayHeight) {
    return static_cast<float>(rawY - RAW_Y_MIN) * displayHeight / (RAW_Y_MAX - RAW_Y_MIN + 1);
}

class MultiTouchInputMapperTest : public TouchInputMapperTest {
public:
    void prepareAxes(int axes);
    void processPosition(MultiTouchInputMapper *mapper, int32_t x, int32_t y);
    void processTouchMajor(MultiTouchInputMapper *mapper, int32_t touchMajor);
    void processTouchMinor(MultiTouchInputMapper *mapper, int32_t touchMinor);
    void processToolMajor(MultiTouchInputMapper *mapper, int32_t toolMajor);
    void processToolMinor(MultiTouchInputMapper *mapper, int32_t toolMinor);
    void processOrientation(MultiTouchInputMapper *mapper, int32_t orientation);
    void processPressure(MultiTouchInputMapper *mapper, int32_t pressure);
    void processDistance(MultiTouchInputMapper *mapper, int32_t distance);
    void processId(MultiTouchInputMapper *mapper, int32_t id);
    void processSlot(MultiTouchInputMapper *mapper, int32_t slot);
    void processToolType(MultiTouchInputMapper *mapper, int32_t toolType);
    void processKey(MultiTouchInputMapper *mapper, int32_t code, int32_t value);
    void processTimestamp(MultiTouchInputMapper *mapper, uint32_t value);
    void processMTSync(MultiTouchInputMapper *mapper);
    void processSync(MultiTouchInputMapper *mapper);
};
void MultiTouchInputMapperTest::prepareAxes(int axes) {
    if (axes & POSITION) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_POSITION_X, RAW_X_MIN, RAW_X_MAX, 0, 0);
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_POSITION_Y, RAW_Y_MIN, RAW_Y_MAX, 0, 0);
    }
    if (axes & TOUCH) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_TOUCH_MAJOR, RAW_TOUCH_MIN, RAW_TOUCH_MAX,
                                       0, 0);
        if (axes & MINOR) {
            mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_TOUCH_MINOR, RAW_TOUCH_MIN,
                                           RAW_TOUCH_MAX, 0, 0);
        }
    }
    if (axes & TOOL) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_WIDTH_MAJOR, RAW_TOOL_MIN, RAW_TOOL_MAX, 0,
                                       0);
        if (axes & MINOR) {
            mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_WIDTH_MINOR, RAW_TOOL_MAX,
                                           RAW_TOOL_MAX, 0, 0);
        }
    }
    if (axes & ORIENTATION) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_ORIENTATION, RAW_ORIENTATION_MIN,
                                       RAW_ORIENTATION_MAX, 0, 0);
    }
    if (axes & PRESSURE) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_PRESSURE, RAW_PRESSURE_MIN,
                                       RAW_PRESSURE_MAX, 0, 0);
    }
    if (axes & DISTANCE) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_DISTANCE, RAW_DISTANCE_MIN,
                                       RAW_DISTANCE_MAX, 0, 0);
    }
    if (axes & ID) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_TRACKING_ID, RAW_ID_MIN, RAW_ID_MAX, 0, 0);
    }
    if (axes & SLOT) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_SLOT, RAW_SLOT_MIN, RAW_SLOT_MAX, 0, 0);
        mFakeEventHub->setAbsoluteAxisValue(DEVICE_ID, ABS_MT_SLOT, 0);
    }
    if (axes & TOOL_TYPE) {
        mFakeEventHub->addAbsoluteAxis(DEVICE_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_MAX, 0, 0);
    }
}
void MultiTouchInputMapperTest::processPosition(MultiTouchInputMapper *mapper, int32_t x,
                                                int32_t y) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, x);
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, y);
}
void MultiTouchInputMapperTest::processTouchMajor(MultiTouchInputMapper *mapper,
                                                  int32_t touchMajor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MAJOR, touchMajor);
}
void MultiTouchInputMapperTest::processTouchMinor(MultiTouchInputMapper *mapper,
                                                  int32_t touchMinor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MINOR, touchMinor);
}
void MultiTouchInputMapperTest::processToolMajor(MultiTouchInputMapper *mapper, int32_t toolMajor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_WIDTH_MAJOR, toolMajor);
}
void MultiTouchInputMapperTest::processToolMinor(MultiTouchInputMapper *mapper, int32_t toolMinor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_WIDTH_MINOR, toolMinor);
}
void MultiTouchInputMapperTest::processOrientation(MultiTouchInputMapper *mapper,
                                                   int32_t orientation) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_ORIENTATION, orientation);
}
void MultiTouchInputMapperTest::processPressure(MultiTouchInputMapper *mapper, int32_t pressure) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_PRESSURE, pressure);
}
void MultiTouchInputMapperTest::processDistance(MultiTouchInputMapper *mapper, int32_t distance) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_DISTANCE, distance);
}
void MultiTouchInputMapperTest::processId(MultiTouchInputMapper *mapper, int32_t id) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, id);
}
void MultiTouchInputMapperTest::processSlot(MultiTouchInputMapper *mapper, int32_t slot) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, slot);
}
void MultiTouchInputMapperTest::processToolType(MultiTouchInputMapper *mapper, int32_t toolType) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, toolType);
}
void MultiTouchInputMapperTest::processKey(MultiTouchInputMapper *mapper, int32_t code,
                                           int32_t value) {
    process(mapper, ARBITRARY_TIME, EV_KEY, code, value);
}
void MultiTouchInputMapperTest::processTimestamp(MultiTouchInputMapper *mapper, uint32_t value) {
    process(mapper, ARBITRARY_TIME, EV_MSC, MSC_TIMESTAMP, value);
}
void MultiTouchInputMapperTest::processMTSync(MultiTouchInputMapper *mapper) {
    process(mapper, ARBITRARY_TIME, EV_SYN, SYN_MT_REPORT, 0);
}
void MultiTouchInputMapperTest::processSync(MultiTouchInputMapper *mapper) {
    process(mapper, ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
}
} // namespace android

#endif // MULTITOUCHINPUTFUZZER_MULTITOUCHINPUTHELPERCLASSES_H_
