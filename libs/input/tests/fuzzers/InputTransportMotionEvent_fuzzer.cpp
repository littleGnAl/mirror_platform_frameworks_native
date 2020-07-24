/*
 * Copyright (C) 2010 The Android Open Source Project
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
#include <input/InputTransport.h>

namespace android {

extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
    FuzzedDataProvider tester(reinterpret_cast<const uint8_t*>(data), size);

    sp<InputChannel> serverChannel, clientChannel;
    PreallocatedInputEventFactory mEventFactory;

    std::string channelName = tester.ConsumeRandomLengthString(500);

    status_t result = InputChannel::openInputChannelPair(channelName, serverChannel, clientChannel);

    if (result != OK) {
        return 0;
    }

    InputPublisher* mPublisher = new InputPublisher(serverChannel);
    InputConsumer* mConsumer = new InputConsumer(clientChannel);

    uint32_t seq = tester.ConsumeIntegral<uint32_t>();
    int32_t deviceId = tester.ConsumeIntegral<int32_t>();
    int32_t source = tester.ConsumeIntegral<int32_t>();
    int32_t displayId = tester.ConsumeIntegralInRange<int32_t>(0, 2) - 1;
    int32_t action = tester.ConsumeIntegral<int32_t>();
    int32_t actionButton = tester.ConsumeIntegral<int32_t>();
    int32_t flags = 1;
    int32_t edgeFlags = tester.ConsumeIntegralInRange<int32_t>(0, 10);
    int32_t metaState = tester.ConsumeIntegral<int32_t>();
    int32_t buttonState = tester.ConsumeIntegral<int32_t>();
    MotionClassification classification = MotionClassification::NONE;
    float xOffset = tester.ConsumeFloatingPoint<float>();
    float yOffset = tester.ConsumeFloatingPoint<float>();
    float xPrecision = tester.ConsumeFloatingPoint<float>();
    float yPrecision = tester.ConsumeFloatingPoint<float>();
    int64_t downTime = tester.ConsumeIntegral<int64_t>();
    int64_t eventTime = tester.ConsumeIntegral<int64_t>();
    int32_t pointerCount = tester.ConsumeIntegralInRange<int32_t>(0, 16);

    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = (i + 2) % pointerCount;
        pointerProperties[i].toolType = tester.ConsumeIntegralInRange<int32_t>(0, 5);

        pointerCoords[i].clear();
        for (size_t j = 0; j < tester.ConsumeIntegralInRange<int32_t>(0, 48); j++) {
            pointerCoords[i].setAxisValue(tester.ConsumeIntegralInRange<int32_t>(0, 48),
                                          tester.ConsumeFloatingPoint<float>());
        }
    }

    mPublisher->publishMotionEvent(seq, deviceId, source, displayId, action, actionButton, flags,
                                   edgeFlags, metaState, buttonState, classification, xOffset,
                                   yOffset, xPrecision, yPrecision, downTime, eventTime,
                                   pointerCount, pointerProperties, pointerCoords);

    uint32_t consumeSeq;
    InputEvent* event;
    int64_t frameTime = tester.ConsumeIntegral<int64_t>();
    mConsumer->consume(&mEventFactory, true, frameTime, &consumeSeq, &event);

    // Free up the resources
    if (mPublisher) {
        delete mPublisher;
        mPublisher = nullptr;
    }

    if (mConsumer) {
        delete mConsumer;
        mConsumer = nullptr;
    }

    serverChannel.clear();
    clientChannel.clear();

    return 0;
}

} // namespace android