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
#include "tests/fuzzers/TestInputListenerLibrary/TestInputListener.h"
#include "tests/fuzzers/commonHeaders/InputReaderHelperClasses.h"
#include "tests/fuzzers/commonHeaders/SwitchMapperHelperClasses.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider tester(data, size);

    if (size > 150) {
        const int32_t DEVICE_ID = tester.ConsumeIntegralInRange<int32_t>(0, 5);
        std::unique_ptr<InputMapperTest> imt = std::make_unique<InputMapperTest>();

        imt->SetUp(&tester);

        InputDevice* mDevice = imt->GetmDevice();
        sp<FakeInputReaderPolicy> mFakePolicy = imt->GetmFakePolicy();
        sp<FakeEventHub> mFakeEventHub = imt->GetmFakeEventHub();

        SwitchInputMapper* mapper = new SwitchInputMapper(mDevice);
        imt->addMapperAndConfigure(mapper);
        mapper->getSources();

        // GetSwitchState
        mapper = new SwitchInputMapper(mDevice);
        imt->addMapperAndConfigure(mapper);
        mFakeEventHub->setSwitchState(DEVICE_ID, SW_LID,
                                      tester.ConsumeIntegralInRange<int32_t>(0, 5));
        mFakeEventHub->setSwitchState(DEVICE_ID, SW_LID,
                                      tester.ConsumeIntegralInRange<int32_t>(0, 5));
        // Process

        mapper = new SwitchInputMapper(mDevice);
        imt->addMapperAndConfigure(mapper);
        InputMapperTest::process(mapper, ARBITRARY_TIME, EV_SW, SW_LID,
                                 tester.ConsumeIntegralInRange<int32_t>(0, 5));
        InputMapperTest::process(mapper, ARBITRARY_TIME, EV_SW, SW_JACK_PHYSICAL_INSERT,
                                 tester.ConsumeIntegralInRange<int32_t>(0, 5));
        InputMapperTest::process(mapper, ARBITRARY_TIME, EV_SW, SW_HEADPHONE_INSERT,
                                 tester.ConsumeIntegralInRange<int32_t>(0, 5));
        InputMapperTest::process(mapper, ARBITRARY_TIME, EV_SYN, SYN_REPORT,
                                 tester.ConsumeIntegralInRange<int32_t>(0, 5));

        // teardown
        imt->TearDown();
    }
    return 0;
}

} // namespace android