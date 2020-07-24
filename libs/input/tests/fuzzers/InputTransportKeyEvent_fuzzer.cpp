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

    // Setup
    sp<InputChannel> serverChannel, clientChannel;
    PreallocatedInputEventFactory mEventFactory;

    std::string channelName = tester.ConsumeRandomLengthString(500);

    status_t result = InputChannel::openInputChannelPair(channelName, serverChannel, clientChannel);

    if (result != OK) {
        return 0;
    }

    InputPublisher* mPublisher = new InputPublisher(serverChannel);
    InputConsumer* mConsumer = new InputConsumer(clientChannel);

    // Key Event
    uint32_t seq = tester.ConsumeIntegral<uint32_t>();
    int32_t deviceId = tester.ConsumeIntegral<int32_t>();
    int32_t source = tester.ConsumeIntegral<int32_t>();
    int32_t displayId = tester.ConsumeIntegralInRange<int32_t>(0, 2) - 1;
    int32_t action = tester.ConsumeIntegralInRange<int32_t>(0, 3);
    int32_t flags = tester.ConsumeIntegral<int32_t>();
    int32_t keyCode = tester.ConsumeIntegral<int32_t>();
    int32_t scanCode = tester.ConsumeIntegral<int32_t>();
    int32_t metaState = tester.ConsumeIntegral<int32_t>();
    int32_t repeatCount = tester.ConsumeIntegral<int32_t>();
    int64_t downTime = tester.ConsumeIntegral<int64_t>();
    int64_t eventTime = tester.ConsumeIntegral<int64_t>();

    mPublisher->publishKeyEvent(seq, deviceId, source, displayId, action, flags, keyCode, scanCode,
                                metaState, repeatCount, downTime, eventTime);

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