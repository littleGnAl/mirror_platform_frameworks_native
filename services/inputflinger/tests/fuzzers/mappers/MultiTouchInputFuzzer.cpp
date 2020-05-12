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
#include "tests/fuzzers/commonHeaders/MultiTouchInputHelperClasses.h"

// TODO : Unhardcode names + values for configuration properties

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider tester(data, size);

    // Process_NormalMultiTouchGesture_WithoutTrackingIds

    std::unique_ptr<MultiTouchInputMapperTest> mmt = std::make_unique<MultiTouchInputMapperTest>();

    mmt->SetUp(&tester);

    InputDevice* mDevice = mmt->GetmDevice();
    FakeInputReaderContext* mFakeContext = mmt->GetmFakeContext();
    sp<FakeInputReaderPolicy> mFakePolicy = mmt->GetmFakePolicy();
    sp<FakeEventHub> mFakeEventHub = mmt->GetmFakeEventHub();

    MultiTouchInputMapper* mapper = new MultiTouchInputMapper(mDevice);

    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");

    mmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION | MultiTouchInputMapperTest::TOUCH |
                     MultiTouchInputMapperTest::TOOL | MultiTouchInputMapperTest::PRESSURE |
                     MultiTouchInputMapperTest::ORIENTATION | MultiTouchInputMapperTest::ID |
                     MultiTouchInputMapperTest::MINOR | MultiTouchInputMapperTest::DISTANCE);
    mmt->prepareVirtualKeys();
    mmt->addMapperAndConfigure(mapper);
    mFakeContext->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);
    ////NotifyMotionArgs motionArgs;
    // Two fingers down at once.
    int32_t x1 = tester.ConsumeIntegralInRange<int32_t>(0, 1000),
            y1 = tester.ConsumeIntegralInRange<int32_t>(0, 1250),
            x2 = tester.ConsumeIntegralInRange<int32_t>(0, 500),
            y2 = tester.ConsumeIntegralInRange<int32_t>(0, 900);
    mmt->processPosition(mapper, x1, y1);
    mmt->processMTSync(mapper);
    mmt->processPosition(mapper, x2, y2);
    mmt->processMTSync(mapper);
    mmt->processSync(mapper);

    // Move.
    x1 += tester.ConsumeIntegralInRange<int32_t>(0, 25);
    y1 += tester.ConsumeIntegralInRange<int32_t>(0, 25);
    x2 += tester.ConsumeIntegralInRange<int32_t>(0, 25);
    y2 -= tester.ConsumeIntegralInRange<int32_t>(0, 25);
    mmt->processPosition(mapper, x1, y1);
    mmt->processMTSync(mapper);
    mmt->processPosition(mapper, x2, y2);
    mmt->processMTSync(mapper);
    mmt->processSync(mapper);

    // Second finger up.
    x1 += tester.ConsumeIntegralInRange<int32_t>(-800, 800);
    y1 -= tester.ConsumeIntegralInRange<int32_t>(-800, 800);
    mmt->processPosition(mapper, x1, y1);
    mmt->processMTSync(mapper);
    mmt->processSync(mapper);

    // Last finger up.
    mmt->processMTSync(mapper);
    mmt->processSync(mapper);

    MultiTouchInputMapper* mapper2 = new MultiTouchInputMapper(mDevice);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(tester.ConsumeIntegralInRange(-1, 4));
    mmt->addConfigurationProperty("touch.size.calibration",
                                  tester.ConsumeBool() ? "diameter" : "area");
    mmt->addConfigurationProperty("touch.size.scale", tester.ConsumeRandomLengthString(8).data());
    mmt->addConfigurationProperty("touch.size.bias", tester.ConsumeRandomLengthString(8).data());
    mmt->addConfigurationProperty("touch.size.isSummed",
                                  tester.ConsumeRandomLengthString(8).data());
    mmt->addConfigurationProperty("touch.size.calibration",
                                  tester.ConsumeRandomLengthString(8).data());
    mmt->addConfigurationProperty("touch.pressure.calibration",
                                  tester.ConsumeRandomLengthString(8).data());
    mmt->addConfigurationProperty("touch.pressure.scale",
                                  tester.ConsumeRandomLengthString(8).data());

    int32_t axesFlag = 0;
    int32_t loopCount = tester.ConsumeIntegralInRange(0, 12);
    for (int32_t i = 0; i < loopCount; i++) {
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
                axesFlag |= tester.ConsumeIntegral<int32_t>();
                break;
            case 9:
                axesFlag |= tester.ConsumeIntegral<int32_t>();
                break;
            case 10:
                axesFlag |= tester.ConsumeIntegral<int32_t>();
                break;
            default:
                break;
        }
    }

    mmt->prepareAxes(axesFlag);
    mmt->addMapperAndConfigure(mapper2);
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

    mmt->processPosition(mapper2, rawX, rawY);
    mmt->processTouchMajor(mapper2, rawTouchMajor);
    mmt->processTouchMinor(mapper2, rawTouchMinor);
    mmt->processToolMajor(mapper2, rawToolMajor);
    mmt->processToolMinor(mapper2, rawToolMinor);
    mmt->processPressure(mapper2, rawPressure);
    mmt->processOrientation(mapper2, rawOrientation);
    mmt->processDistance(mapper2, rawDistance);
    mmt->processId(mapper2, id);
    mmt->processMTSync(mapper2);
    mmt->processSync(mapper2);

    // loop the buttons
    mmt->processKey(mapper2, tester.ConsumeIntegralInRange(-1, 289), tester.ConsumeBool());
    mmt->processSync(mapper2);

    mmt->processKey(mapper2, tester.ConsumeIntegralInRange(-1, 289), tester.ConsumeBool());
    mmt->processSync(mapper2);
    // release touch
    mmt->processId(mapper2, -1);
    mmt->processSync(mapper2);

    // stylus
    mmt->processKey(mapper2, tester.ConsumeIntegralInRange(0x100, 0x151), tester.ConsumeBool());
    mmt->processKey(mapper2, tester.ConsumeIntegralInRange(0x100, 0x151), tester.ConsumeBool());
    mmt->processSync(mapper2);

    // MT tool type trumps BTN tool types: MT_TOOL_PEN
    mmt->processToolType(mapper2, tester.ConsumeIntegralInRange(-1, 17));
    mmt->processSync(mapper2);

    // WhenMapperIsReset_TimestampIsCleared
    MultiTouchInputMapper* mapper12 = new MultiTouchInputMapper(mDevice);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(DISPLAY_ORIENTATION_0);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addMapperAndConfigure(mapper12);

    // Send a touch event with a timestamp
    mmt->processPosition(mapper12, tester.ConsumeIntegralInRange(-1, 289),
                         tester.ConsumeIntegralInRange(-1, 289));
    mmt->processTimestamp(mapper12, tester.ConsumeIntegralInRange(0, 3));
    mmt->processMTSync(mapper12);
    mmt->processSync(mapper12);

    // Since the data accumulates, and new timestamp has not arrived, deviceTimestamp won't change
    mmt->processPosition(mapper12, tester.ConsumeIntegralInRange(-1, 289),
                         tester.ConsumeIntegralInRange(-1, 289));
    mmt->processMTSync(mapper12);
    mmt->processSync(mapper12);

    mapper12->reset(/* when */ 0);
    // After the mapper12 is reset, deviceTimestamp should become zero again
    mmt->processPosition(mapper12, tester.ConsumeIntegralInRange(-1, 289),
                         tester.ConsumeIntegralInRange(-1, 289));
    mmt->processMTSync(mapper12);
    mmt->processSync(mapper12);

    // VideoFrames_ReceivedByListener
    MultiTouchInputMapper* mapper18 = new MultiTouchInputMapper(mDevice);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->prepareDisplay(DISPLAY_ORIENTATION_0);
    mmt->addMapperAndConfigure(mapper18);

    // Unrotated video frame
    TouchVideoFrame frame(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    std::vector<TouchVideoFrame> frames{frame};
    mFakeEventHub->setVideoFrames({{mDevice->getId(), frames}});
    mmt->processPosition(mapper18, tester.ConsumeIntegralInRange(-1, 289),
                         tester.ConsumeIntegralInRange(-1, 289));
    mmt->processSync(mapper18);

    // Subsequent touch events should not have any videoframes
    // This is implemented separately in FakeEventHub,
    // but that should match the behaviour of TouchVideoDevice.
    mmt->processPosition(mapper18, tester.ConsumeIntegralInRange(-1, 289),
                         tester.ConsumeIntegralInRange(-1, 289));
    mmt->processSync(mapper18);

    // VideoFrames_AreRotated
    MultiTouchInputMapper* mapper19 = new MultiTouchInputMapper(mDevice);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->addMapperAndConfigure(mapper19);
    // Unrotated video frame
    TouchVideoFrame frame2(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});

    // Test all 4 orientations
    for (int32_t orientation : {DISPLAY_ORIENTATION_0, DISPLAY_ORIENTATION_90,
                                DISPLAY_ORIENTATION_180, DISPLAY_ORIENTATION_270}) {
        mmt->clearViewports();
        mmt->prepareDisplay(orientation);
        std::vector<TouchVideoFrame> frames2{frame2};
        mFakeEventHub->setVideoFrames({{mDevice->getId(), frames2}});
        mmt->processPosition(mapper19, tester.ConsumeIntegralInRange(-1, 289),
                             tester.ConsumeIntegralInRange(-1, 289));
        mmt->processSync(mapper19);
        frames2[0].rotate(orientation);
    }

    // VideoFrames_MultipleFramesAreRotated
    MultiTouchInputMapper* mapper20 = new MultiTouchInputMapper(mDevice);
    mmt->prepareAxes(MultiTouchInputMapperTest::POSITION);
    mmt->addConfigurationProperty("touch.deviceType", "touchScreen");
    mmt->addMapperAndConfigure(mapper20);
    // Unrotated video frames. There's no rule that they must all have the same dimensions,
    // so mix these.
    TouchVideoFrame frame11(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    TouchVideoFrame frame21(3, 3, {0, 1, 2, 3, 4, 5, 6, 7, 8}, {1, 3});
    TouchVideoFrame frame31(2, 2, {10, 20, 10, 0}, {1, 4});
    std::vector<TouchVideoFrame> frames1{frame11, frame21, frame31};
    // NotifyMotionArgs motionArgs;
    mmt->prepareDisplay(DISPLAY_ORIENTATION_90);
    mFakeEventHub->setVideoFrames({{mDevice->getId(), frames1}});
    mmt->processPosition(mapper20, tester.ConsumeIntegralInRange(-1, 289),
                         tester.ConsumeIntegralInRange(-1, 289));
    mmt->processSync(mapper20);
    std::for_each(frames1.begin(), frames1.end(),
                  [](TouchVideoFrame& frame) { frame.rotate(DISPLAY_ORIENTATION_90); });

    mmt->TearDown();

    return 0;
}

} // namespace android