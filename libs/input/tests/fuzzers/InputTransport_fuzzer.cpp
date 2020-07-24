/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define AXIS_TYPE_MAX_LENGTH 48

namespace android {

enum class EVENT_TYPE {
    KEY_EVENT = 0,
    MOTION_EVENT = 1,
};
static const size_t MAX_EVENT_TYPE_LENGTH = 2;

extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
    FuzzedDataProvider fdp(reinterpret_cast<const uint8_t*>(data), size);

    // Setup
    sp<InputChannel> serverChannel, clientChannel;
    PreallocatedInputEventFactory mEventFactory;

    std::string channelName = fdp.ConsumeRandomLengthString(75);

    status_t result = InputChannel::openInputChannelPair(channelName, serverChannel, clientChannel);

    if (result != OK) {
        return 0;
    }

    auto mPublisher = std::make_unique<InputPublisher>(serverChannel);
    auto mConsumer = std::make_unique<InputConsumer>(clientChannel);

    uint32_t seq = fdp.ConsumeIntegral<uint32_t>();
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t source = fdp.ConsumeIntegral<int32_t>();
    int32_t displayId = fdp.ConsumeIntegral<int32_t>();
    int32_t action = fdp.ConsumeIntegral<int32_t>();
    // int32_t action = 7;

    int32_t flags = fdp.ConsumeIntegral<int32_t>();
    int32_t metaState = fdp.ConsumeIntegral<int32_t>();
    int64_t downTime = fdp.ConsumeIntegral<int64_t>();
    int64_t eventTime = fdp.ConsumeIntegral<int64_t>();

    EVENT_TYPE eventType =
            static_cast<EVENT_TYPE>(fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_EVENT_TYPE_LENGTH));

    switch (eventType) {
        case EVENT_TYPE::KEY_EVENT: {
            int32_t keyCode = fdp.ConsumeIntegral<int32_t>();
            int32_t scanCode = fdp.ConsumeIntegral<int32_t>();
            int32_t repeatCount = fdp.ConsumeIntegral<int32_t>();

            mPublisher->publishKeyEvent(seq, deviceId, source, displayId, action, flags, keyCode,
                                        scanCode, metaState, repeatCount, downTime, eventTime);

            break;
        }
        case EVENT_TYPE::MOTION_EVENT: {
            int32_t actionButton = fdp.ConsumeIntegral<int32_t>();
            int32_t edgeFlags = fdp.ConsumeIntegral<int32_t>();
            int32_t buttonState = fdp.ConsumeIntegral<int32_t>();
            MotionClassification classification =
                    static_cast<MotionClassification>(fdp.ConsumeIntegral<uint8_t>());
            float xOffset = fdp.ConsumeFloatingPoint<float>();
            float yOffset = fdp.ConsumeFloatingPoint<float>();
            float xPrecision = fdp.ConsumeFloatingPoint<float>();
            float yPrecision = fdp.ConsumeFloatingPoint<float>();
            uint32_t pointerCount = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_POINTERS);

            PointerProperties pointerProperties[pointerCount];
            PointerCoords pointerCoords[pointerCount];

            for (size_t i = 0; i < pointerCount; i++) {
                pointerProperties[i].clear();
                pointerProperties[i].id = (i + 2) % pointerCount;
                pointerProperties[i].toolType = fdp.ConsumeIntegral<int32_t>();

                pointerCoords[i].clear();
                for (size_t j = 0;
                     j < fdp.ConsumeIntegralInRange<uint32_t>(0, AXIS_TYPE_MAX_LENGTH); j++) {
                    pointerCoords[i]
                            .setAxisValue(fdp.ConsumeIntegralInRange<int32_t>(0,
                                                                              AXIS_TYPE_MAX_LENGTH),
                                          fdp.ConsumeFloatingPoint<float>());
                }
            }

            mPublisher->publishMotionEvent(seq, deviceId, source, displayId, action, actionButton,
                                           flags, edgeFlags, metaState, buttonState, classification,
                                           xOffset, yOffset, xPrecision, yPrecision, downTime,
                                           eventTime, pointerCount, pointerProperties,
                                           pointerCoords);

            break;
        }
    }

    uint32_t consumeSeq;
    InputEvent* event;
    int64_t frameTime = fdp.ConsumeIntegral<int64_t>();
    mConsumer->consume(&mEventFactory, true, frameTime, &consumeSeq, &event);

    uint32_t finishedSeq = 0;
    bool handled = false;
    mConsumer->sendFinishedSignal(seq, true);

    mPublisher->receiveFinishedSignal(&finishedSeq, &handled);

    return 0;
}

} // namespace android