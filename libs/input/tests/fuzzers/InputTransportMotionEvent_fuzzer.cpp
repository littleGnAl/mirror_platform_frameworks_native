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
    FuzzedDataProvider fdp(reinterpret_cast<const uint8_t*>(data), size);

    sp<InputChannel> serverChannel, clientChannel;
    PreallocatedInputEventFactory mEventFactory;

    std::string channelName = fdp.ConsumeRandomLengthString(500);

    status_t result = InputChannel::openInputChannelPair(channelName, serverChannel, clientChannel);

    if (result != OK) {
        return 0;
    }

    InputPublisher* mPublisher = new InputPublisher(serverChannel);
    InputConsumer* mConsumer = new InputConsumer(clientChannel);

    uint32_t seq = fdp.ConsumeIntegral<uint32_t>();
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t source = fdp.ConsumeIntegral<int32_t>();
    int32_t displayId = fdp.ConsumeIntegralInRange<int32_t>(0, 2) - 1;
    int32_t action = fdp.ConsumeIntegral<int32_t>();
    int32_t actionButton = fdp.ConsumeIntegral<int32_t>();
    int32_t flags = 1;
    int32_t edgeFlags = fdp.ConsumeIntegralInRange<int32_t>(0, 10);
    int32_t metaState = fdp.ConsumeIntegral<int32_t>();
    int32_t buttonState = fdp.ConsumeIntegral<int32_t>();
    MotionClassification classification = MotionClassification::NONE;
    float xOffset = fdp.ConsumeFloatingPoint<float>();
    float yOffset = fdp.ConsumeFloatingPoint<float>();
    float xPrecision = fdp.ConsumeFloatingPoint<float>();
    float yPrecision = fdp.ConsumeFloatingPoint<float>();
    int64_t downTime = fdp.ConsumeIntegral<int64_t>();
    int64_t eventTime = fdp.ConsumeIntegral<int64_t>();
    uint32_t pointerCount = fdp.ConsumeIntegralInRange<int32_t>(0, 16);

    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = (i + 2) % pointerCount;
        pointerProperties[i].toolType = fdp.ConsumeIntegralInRange<int32_t>(0, 5);

        pointerCoords[i].clear();
        for (size_t j = 0; j < fdp.ConsumeIntegralInRange<uint32_t>(0, 48); j++) {
            pointerCoords[i].setAxisValue(fdp.ConsumeIntegralInRange<int32_t>(0, 48),
                                          fdp.ConsumeFloatingPoint<float>());
        }
    }

    mPublisher->publishMotionEvent(seq, deviceId, source, displayId, action, actionButton, flags,
                                   edgeFlags, metaState, buttonState, classification, xOffset,
                                   yOffset, xPrecision, yPrecision, downTime, eventTime,
                                   pointerCount, pointerProperties, pointerCoords);

    uint32_t consumeSeq;
    InputEvent* event;
    int64_t frameTime = fdp.ConsumeIntegral<int64_t>();
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