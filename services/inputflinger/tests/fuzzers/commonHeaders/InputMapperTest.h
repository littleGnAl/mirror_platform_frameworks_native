
#ifndef FUZZ_INPUTMAPPERTEST_H
#define FUZZ_INPUTMAPPERTEST_H

#include <InputDevice.h>
#include <InputMapper.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <input/DisplayViewport.h>
#include "InputReaderHelperClasses.h"
#include "tests/fuzzers/TestInputListenerLibrary/TestInputListener.h"

namespace android {

class InputMapperTest {
    // make testing easier
public:
    static const char* DEVICE_NAME;
    static const char* DEVICE_LOCATION;
    static const int32_t DEVICE_ID;
    static const int32_t DEVICE_GENERATION;
    static const int32_t DEVICE_CONTROLLER_NUMBER;
    static const uint32_t DEVICE_CLASSES;
    sp<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    sp<TestInputListener> mFakeListener;
    FakeInputReaderContext* mFakeContext;
    InputDevice* mDevice;
    virtual void SetUp(FuzzedDataProvider* fdp) {
        const std::string DEVICE_NAME = fdp->ConsumeRandomLengthString(16);
        const std::string DEVICE_LOCATION = fdp->ConsumeRandomLengthString(12);
        const int32_t DEVICE_ID = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
        const int32_t DEVICE_GENERATION = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
        const int32_t DEVICE_CONTROLLER_NUMBER = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
        const uint32_t DEVICE_CLASSES = fdp->ConsumeIntegralInRange<uint32_t>(0, 5);

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
    void addConfigurationProperty(const char* key, const char* value) {
        mFakeEventHub->addConfigurationProperty(mDevice->getId(), String8(key), String8(value));
    }
    void configureDevice(uint32_t changes) {
        const InputReaderConfiguration* policy = mFakePolicy->getReaderConfiguration();
        mDevice->configure(ARBITRARY_TIME, policy, changes);
    }
    void addMapperAndConfigure(InputMapper* mapper) {
        mDevice->addMapper(mapper);
        configureDevice(0);
        mDevice->reset(ARBITRARY_TIME);
    }
    void setDisplayInfoAndReconfigure(int32_t displayId, int32_t width, int32_t height,
                                      int32_t orientation, const std::string& uniqueId,
                                      std::optional<uint8_t> physicalPort,
                                      ViewportType viewportType) {
        mFakePolicy->addDisplayViewport(displayId, width, height, orientation, uniqueId,
                                        physicalPort, viewportType);
        configureDevice(InputReaderConfiguration::CHANGE_DISPLAY_INFO);
    }
    void clearViewports() { mFakePolicy->clearViewports(); }
    static void process(InputMapper* mapper, nsecs_t when, int32_t type, int32_t code,
                        int32_t value) {
        RawEvent event;
        event.when = when;
        event.deviceId = mapper->getDeviceId();
        event.type = type;
        event.code = code;
        event.value = value;
        mapper->process(&event);
    }
    static void assertMotionRange(const InputDeviceInfo& info, int32_t axis, uint32_t source,
                                  float min, float max, float flat, float fuzz) {
        /*const InputDeviceInfo::MotionRange* range = info.getMotionRange(axis, source);
        ASSERT_TRUE(range != nullptr) << "Axis: " << axis << " Source: " << source;
        ASSERT_EQ(axis, range->axis) << "Axis: " << axis << " Source: " << source;
        ASSERT_EQ(source, range->source) << "Axis: " << axis << " Source: " << source;
        ASSERT_NEAR(min, range->min, EPSILON) << "Axis: " << axis << " Source: " << source;
        ASSERT_NEAR(max, range->max, EPSILON) << "Axis: " << axis << " Source: " << source;
        ASSERT_NEAR(flat, range->flat, EPSILON) << "Axis: " << axis << " Source: " << source;
        ASSERT_NEAR(fuzz, range->fuzz, EPSILON) << "Axis: " << axis << " Source: " << source;*/
    }
    static void assertPointerCoords(const PointerCoords& coords, float x, float y, float pressure,
                                    float size, float touchMajor, float touchMinor, float toolMajor,
                                    float toolMinor, float orientation, float distance) {
        /*ASSERT_NEAR(x, coords.getAxisValue(AMOTION_EVENT_AXIS_X), 1);
        ASSERT_NEAR(y, coords.getAxisValue(AMOTION_EVENT_AXIS_Y), 1);
        ASSERT_NEAR(pressure, coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE), EPSILON);
        ASSERT_NEAR(size, coords.getAxisValue(AMOTION_EVENT_AXIS_SIZE), EPSILON);
        ASSERT_NEAR(touchMajor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR), 1);
        ASSERT_NEAR(touchMinor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR), 1);
        ASSERT_NEAR(toolMajor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR), 1);
        ASSERT_NEAR(toolMinor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR), 1);
        ASSERT_NEAR(orientation, coords.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION), EPSILON);
        ASSERT_NEAR(distance, coords.getAxisValue(AMOTION_EVENT_AXIS_DISTANCE), EPSILON);*/
    }
    static void assertPosition(const sp<FakePointerController>& controller, float x, float y) {
        float actualX, actualY;
        controller->getPosition(&actualX, &actualY);
        // ASSERT_NEAR(x, actualX, 1);
        // ASSERT_NEAR(y, actualY, 1);
    }
    InputDevice* GetmDevice() { return mDevice; }

    FakeInputReaderContext* GetmFakeContext() { return mFakeContext; }

    sp<FakeInputReaderPolicy> GetmFakePolicy() { return mFakePolicy; }

    sp<FakeEventHub> GetmFakeEventHub() { return mFakeEventHub; }
};

} // namespace android

#endif // FUZZ_INPUTMAPPERTEST_H
