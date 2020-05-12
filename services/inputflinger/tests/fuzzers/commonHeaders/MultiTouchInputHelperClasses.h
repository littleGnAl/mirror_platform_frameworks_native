
#ifndef FUZZ_MULTITOUCHINPUTHELPERS_H
#define FUZZ_MULTITOUCHINPUTHELPERS_H

#include "InputMapperTest.h"
#include "TouchInputMapperTest.h"

namespace android {

class MultiTouchInputMapperTest : public TouchInputMapperTest {
public:
    void prepareAxes(int axes);

    void processPosition(MultiTouchInputMapper* mapper, int32_t x, int32_t y);
    void processTouchMajor(MultiTouchInputMapper* mapper, int32_t touchMajor);
    void processTouchMinor(MultiTouchInputMapper* mapper, int32_t touchMinor);
    void processToolMajor(MultiTouchInputMapper* mapper, int32_t toolMajor);
    void processToolMinor(MultiTouchInputMapper* mapper, int32_t toolMinor);
    void processOrientation(MultiTouchInputMapper* mapper, int32_t orientation);
    void processPressure(MultiTouchInputMapper* mapper, int32_t pressure);
    void processDistance(MultiTouchInputMapper* mapper, int32_t distance);
    void processId(MultiTouchInputMapper* mapper, int32_t id);
    void processSlot(MultiTouchInputMapper* mapper, int32_t slot);
    void processToolType(MultiTouchInputMapper* mapper, int32_t toolType);
    void processKey(MultiTouchInputMapper* mapper, int32_t code, int32_t value);
    void processTimestamp(MultiTouchInputMapper* mapper, uint32_t value);
    void processMTSync(MultiTouchInputMapper* mapper);
    void processSync(MultiTouchInputMapper* mapper);
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

void MultiTouchInputMapperTest::processPosition(MultiTouchInputMapper* mapper, int32_t x,
                                                int32_t y) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, x);
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, y);
}

void MultiTouchInputMapperTest::processTouchMajor(MultiTouchInputMapper* mapper,
                                                  int32_t touchMajor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MAJOR, touchMajor);
}

void MultiTouchInputMapperTest::processTouchMinor(MultiTouchInputMapper* mapper,
                                                  int32_t touchMinor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MINOR, touchMinor);
}

void MultiTouchInputMapperTest::processToolMajor(MultiTouchInputMapper* mapper, int32_t toolMajor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_WIDTH_MAJOR, toolMajor);
}

void MultiTouchInputMapperTest::processToolMinor(MultiTouchInputMapper* mapper, int32_t toolMinor) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_WIDTH_MINOR, toolMinor);
}

void MultiTouchInputMapperTest::processOrientation(MultiTouchInputMapper* mapper,
                                                   int32_t orientation) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_ORIENTATION, orientation);
}

void MultiTouchInputMapperTest::processPressure(MultiTouchInputMapper* mapper, int32_t pressure) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_PRESSURE, pressure);
}

void MultiTouchInputMapperTest::processDistance(MultiTouchInputMapper* mapper, int32_t distance) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_DISTANCE, distance);
}

void MultiTouchInputMapperTest::processId(MultiTouchInputMapper* mapper, int32_t id) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, id);
}

void MultiTouchInputMapperTest::processSlot(MultiTouchInputMapper* mapper, int32_t slot) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, slot);
}

void MultiTouchInputMapperTest::processToolType(MultiTouchInputMapper* mapper, int32_t toolType) {
    process(mapper, ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, toolType);
}

void MultiTouchInputMapperTest::processKey(MultiTouchInputMapper* mapper, int32_t code,
                                           int32_t value) {
    process(mapper, ARBITRARY_TIME, EV_KEY, code, value);
}

void MultiTouchInputMapperTest::processTimestamp(MultiTouchInputMapper* mapper, uint32_t value) {
    process(mapper, ARBITRARY_TIME, EV_MSC, MSC_TIMESTAMP, value);
}

void MultiTouchInputMapperTest::processMTSync(MultiTouchInputMapper* mapper) {
    process(mapper, ARBITRARY_TIME, EV_SYN, SYN_MT_REPORT, 0);
}

void MultiTouchInputMapperTest::processSync(MultiTouchInputMapper* mapper) {
    process(mapper, ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
}
} // namespace android

#endif // FUZZ_MULTITOUCHINPUTHELPERS_H
