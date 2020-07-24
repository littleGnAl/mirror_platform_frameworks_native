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

namespace android {

extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
    FuzzedDataProvider fdp(reinterpret_cast<const uint8_t*>(data), size);

    // Setup
    sp<InputChannel> serverChannel, clientChannel;
    PreallocatedInputEventFactory mEventFactory;

    std::string channelName = fdp.ConsumeRandomLengthString(500);

    status_t result = InputChannel::openInputChannelPair(channelName, serverChannel, clientChannel);

    if (result != OK) {
        return 0;
    }

    InputPublisher* mPublisher = new InputPublisher(serverChannel);
    InputConsumer* mConsumer = new InputConsumer(clientChannel);

    // Key Event
    uint32_t seq = fdp.ConsumeIntegral<uint32_t>();
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t source = fdp.ConsumeIntegral<int32_t>();
    int32_t displayId = fdp.ConsumeIntegralInRange<int32_t>(0, 2) - 1;
    int32_t action = fdp.ConsumeIntegralInRange<int32_t>(0, 3);
    int32_t flags = fdp.ConsumeIntegral<int32_t>();
    int32_t keyCode = fdp.ConsumeIntegral<int32_t>();
    int32_t scanCode = fdp.ConsumeIntegral<int32_t>();
    int32_t metaState = fdp.ConsumeIntegral<int32_t>();
    int32_t repeatCount = fdp.ConsumeIntegral<int32_t>();
    int64_t downTime = fdp.ConsumeIntegral<int64_t>();
    int64_t eventTime = fdp.ConsumeIntegral<int64_t>();

    mPublisher->publishKeyEvent(seq, deviceId, source, displayId, action, flags, keyCode, scanCode,
                                metaState, repeatCount, downTime, eventTime);

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