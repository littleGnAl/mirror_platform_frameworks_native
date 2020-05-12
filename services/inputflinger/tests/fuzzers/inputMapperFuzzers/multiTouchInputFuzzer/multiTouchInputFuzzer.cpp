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
#include "include/fuzzTestInputListener.h"
#include "inputMapperFuzzers/include/inputReaderHelperClasses.h"
#include "multiTouchInputHelperClasses.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider tester(data, size);

    const std::string UNIQUE_ID = tester.ConsumeRandomLengthString(50) + ":" +
            static_cast<char>(tester.ConsumeIntegralInRange(0, 10));
    const std::string DEVICE_NAME = tester.ConsumeRandomLengthString(16);
    const std::string DEVICE_LOCATION = tester.ConsumeRandomLengthString(12);
    const int32_t DEVICE_ID = tester.ConsumeIntegralInRange<int>(0, 5);
    const int32_t DEVICE_GENERATION = tester.ConsumeIntegralInRange<int>(0, 5);
    const int32_t DEVICE_CONTROLLER_NUMBER = tester.ConsumeIntegralInRange<int>(0, 5);
    const uint32_t DEVICE_CLASSES = tester.ConsumeIntegralInRange<int>(0, 5);
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

    sp<FakePointerController> mFakePointerController = new FakePointerController();
    mFakePolicy->setPointerController(mDevice->getId(), mFakePointerController);

    // Process_NormalMultiTouchGesture_WithoutTrackingIds
    MultiTouchInputMapperTest *mmt = new MultiTouchInputMapperTest();
    mmt->SetUp();

    MultiTouchInputMapper *mappers[6];

    mappers[0] = new MultiTouchInputMapper(mDevice);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION | MultiTouchInputMapperTest::TOUCH |
                     MultiTouchInputMapperTest::TOOL | MultiTouchInputMapperTest::PRESSURE |
                     MultiTouchInputMapperTest::ORIENTATION | MultiTouchInputMapperTest::ID |
                     MultiTouchInputMapperTest::MINOR | MultiTouchInputMapperTest::DISTANCE);
    mmt->prepareVirtualKeys();
    mmt->addMapperAndConfigure(mappers[0]);
    mFakeContext->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);
    // NotifyMotionArgs motionArgs;
    // Two fingers down at once.
    int32_t x1 = tester.ConsumeIntegralInRange<int>(0, 1000),
            y1 = tester.ConsumeIntegralInRange<int>(0, 1250),
            x2 = tester.ConsumeIntegralInRange<int>(0, 500),
            y2 = tester.ConsumeIntegralInRange<int>(0, 900);
    mmt->processPosition(mappers[0], x1, y1);
    mmt->processMTSync(mappers[0]);
    mmt->processPosition(mappers[0], x2, y2);
    mmt->processMTSync(mappers[0]);
    mmt->processSync(mappers[0]);

    // Move.
    x1 += tester.ConsumeIntegralInRange<int>(0, 25);
    y1 += tester.ConsumeIntegralInRange<int>(0, 25);
    x2 += tester.ConsumeIntegralInRange<int>(0, 25);
    y2 -= tester.ConsumeIntegralInRange<int>(0, 25);
    mmt->processPosition(mappers[0], x1, y1);
    mmt->processMTSync(mappers[0]);
    mmt->processPosition(mappers[0], x2, y2);
    mmt->processMTSync(mappers[0]);
    mmt->processSync(mappers[0]);

    // Second finger up.
    x1 += tester.ConsumeIntegralInRange<int>(-800, 800);
    y1 -= tester.ConsumeIntegralInRange<int>(-800, 800);
    mmt->processPosition(mappers[0], x1, y1);
    mmt->processMTSync(mappers[0]);
    mmt->processSync(mappers[0]);

    // Last finger up.
    mmt->processMTSync(mappers[0]);
    mmt->processSync(mappers[0]);

    mappers[1] = new MultiTouchInputMapper(mDevice);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));
    mmt->addConfigurationProperty("touch.size.calibration",
                                  tester.ConsumeBool() ? "diameter" : "area");
    mmt->addConfigurationProperty("touch.size.scale",
                                  tester.ConsumeBytesWithTerminator<char>(8).data());
    mmt->addConfigurationProperty("touch.size.bias",
                                  tester.ConsumeBytesWithTerminator<char>(8).data());
    mmt->addConfigurationProperty("touch.size.isSummed",
                                  tester.ConsumeBytesWithTerminator<char>(8).data());
    mmt->addConfigurationProperty("touch.size.calibration",
                                  tester.ConsumeBytesWithTerminator<char>(8).data());
    mmt->addConfigurationProperty("touch.pressure.calibration", "amplitude");
    mmt->addConfigurationProperty("touch.pressure.scale",
                                  tester.ConsumeBytesWithTerminator<char>(8).data());

    int axesFlag = 0;
    int loopCount = tester.ConsumeIntegralInRange(0, 12);
    for (int i = 0; i < loopCount; i++) {
        switch (tester.ConsumeIntegralInRange(0, 11)) {
            case 0:
                axesFlag |= MultiTouchInputMapperTest::POSITION;
                break;
            case 1:
                axesFlag |= MultiTouchInputMapperTest::TOUCH;
                break;
            case 2:
                axesFlag |= MultiTouchInputMapperTest::TOOL;
                break;
            case 3:
                axesFlag |= MultiTouchInputMapperTest::PRESSURE;
                break;
            case 4:
                axesFlag |= MultiTouchInputMapperTest::ORIENTATION;
                break;
            case 5:
                axesFlag |= MultiTouchInputMapperTest::ID;
                break;
            case 6:
                axesFlag |= MultiTouchInputMapperTest::MINOR;
                break;
            case 7:
                axesFlag |= MultiTouchInputMapperTest::DISTANCE;
                break;
            case 8:
                axesFlag |= tester.ConsumeIntegral<int>();
                break;
            case 9:
                axesFlag |= tester.ConsumeIntegral<int>();
                break;
            case 10:
                axesFlag |= tester.ConsumeIntegral<int>();
                break;
            default:
                break;
        }
    }

    mmt->prepareAxes(axesFlag);
    mmt->addMapperAndConfigure(mappers[1]);
    // These calculations are based on the input device calibration documentation.
    int32_t rawX = tester.ConsumeIntegralInRange(-1, 1025);
    int32_t rawY = tester.ConsumeIntegralInRange(-1, 1025);
    int32_t rawTouchMajor = tester.ConsumeIntegralInRange(-1, 129);
    int32_t rawTouchMinor = tester.ConsumeIntegralInRange(-1, 129);
    int32_t rawToolMajor = tester.ConsumeIntegralInRange(-1, 129);
    int32_t rawToolMinor = tester.ConsumeIntegralInRange(-1, 129);
    int32_t rawPressure = tester.ConsumeIntegralInRange(-1, 129);
    int32_t rawDistance = tester.ConsumeIntegralInRange(-1, 129);
    int32_t rawOrientation = tester.ConsumeIntegralInRange(-1, 129);
    int32_t id = tester.ConsumeIntegralInRange(-1, 129);

    mmt->processPosition(mappers[1], rawX, rawY);
    mmt->processTouchMajor(mappers[1], rawTouchMajor);
    mmt->processTouchMinor(mappers[1], rawTouchMinor);
    mmt->processToolMajor(mappers[1], rawToolMajor);
    mmt->processToolMinor(mappers[1], rawToolMinor);
    mmt->processPressure(mappers[1], rawPressure);
    mmt->processOrientation(mappers[1], rawOrientation);
    mmt->processDistance(mappers[1], rawDistance);
    mmt->processId(mappers[1], id);
    mmt->processMTSync(mappers[1]);
    mmt->processSync(mappers[1]);

    // loop the buttons
    for (int i = 0; i < tester.ConsumeIntegralInRange(0, 50); i++) {
        mmt->processKey(mappers[1], tester.ConsumeIntegralInRange(-1, 289), tester.ConsumeBool());
        mmt->processSync(mappers[1]);
    }

    // release touch
    mmt->processId(mappers[1], -1);
    mmt->processSync(mappers[1]);

    // stylus
    for (int i = 0; i < tester.ConsumeIntegralInRange(0, 10); i++) {
        mmt->processKey(mappers[1], tester.ConsumeIntegralInRange(0x100, 0x151),
                        tester.ConsumeBool());
    }
    mmt->processSync(mappers[1]);

    // MT tool type trumps BTN tool types: MT_TOOL_PEN
    mmt->processToolType(mappers[1], tester.ConsumeIntegralInRange(-1, 17));
    mmt->processSync(mappers[1]);

    // WhenMapperIsReset_TimestampIsCleared
    mappers[2] = new MultiTouchInputMapper(mDevice);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(DISPLAY_ORIENTATION_0);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addMapperAndConfigure(mappers[2]);

    // Send a touch event with a timestamp
    mmt->processPosition(mappers[2], 100, 100);
    mmt->processTimestamp(mappers[2], 1);
    mmt->processMTSync(mappers[2]);
    mmt->processSync(mappers[2]);

    // Since the data accumulates, and new timestamp has not arrived,
    // deviceTimestamp won't change
    mmt->processPosition(mappers[2], 100, 200);
    mmt->processMTSync(mappers[2]);
    mmt->processSync(mappers[2]);

    mappers[2]->reset(/* when */ 0);
    // After the mappers[2] is reset, deviceTimestamp should become zero again
    mmt->processPosition(mappers[2], 100, 300);
    mmt->processMTSync(mappers[2]);
    mmt->processSync(mappers[2]);

    // VideoFrames_ReceivedByListener
    mappers[3] = new MultiTouchInputMapper(mDevice);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(DISPLAY_ORIENTATION_0);
    mmt->addMapperAndConfigure(mappers[3]);

    // Unrotated video frame
    TouchVideoFrame frame(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    std::vector<TouchVideoFrame> frames{frame};
    mFakeEventHub->setVideoFrames({{mDevice->getId(), frames}});
    mmt->processPosition(mappers[3], 100, 200);
    mmt->processSync(mappers[3]);

    // Subsequent touch events should not have any videoframes
    // This is implemented separately in FakeEventHub,
    // but that should match the behaviour of TouchVideoDevice.
    mmt->processPosition(mappers[3], 200, 200);
    mmt->processSync(mappers[3]);

    // VideoFrames_AreRotated
    mappers[4] = new MultiTouchInputMapper(mDevice);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->addMapperAndConfigure(mappers[4]);
    // Unrotated video frame
    TouchVideoFrame frame2(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});

    // Test all 4 orientations
    for (int32_t orientation : {DISPLAY_ORIENTATION_0, DISPLAY_ORIENTATION_90,
                                DISPLAY_ORIENTATION_180, DISPLAY_ORIENTATION_270}) {
        mmt->clearViewports();
        mmt->prepareDisplay(orientation);
        std::vector<TouchVideoFrame> frames2{frame2};
        mFakeEventHub->setVideoFrames({{mDevice->getId(), frames2}});
        mmt->processPosition(mappers[4], 100, 200);
        mmt->processSync(mappers[4]);
        frames2[0].rotate(orientation);
    }

    // VideoFrames_MultipleFramesAreRotated
    mappers[5] = new MultiTouchInputMapper(mDevice);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->addMapperAndConfigure(mappers[5]);
    // Unrotated video frames. There's no rule that they must all have the same
    // dimensions, so mix these.
    TouchVideoFrame frame11(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    TouchVideoFrame frame21(3, 3, {0, 1, 2, 3, 4, 5, 6, 7, 8}, {1, 3});
    TouchVideoFrame frame31(2, 2, {10, 20, 10, 0}, {1, 4});
    std::vector<TouchVideoFrame> frames1{frame11, frame21, frame31};
    // NotifyMotionArgs motionArgs;
    mmt->prepareDisplay(DISPLAY_ORIENTATION_90);
    mFakeEventHub->setVideoFrames({{mDevice->getId(), frames1}});
    mmt->processPosition(mappers[5], 100, 200);
    mmt->processSync(mappers[5]);
    std::for_each(frames1.begin(), frames1.end(),
                  [](TouchVideoFrame &frame) { frame.rotate(DISPLAY_ORIENTATION_90); });

    mmt->TearDown();
    delete mmt;
    delete mDevice;
    delete mFakeContext;

    return 0;
}

} // namespace android
