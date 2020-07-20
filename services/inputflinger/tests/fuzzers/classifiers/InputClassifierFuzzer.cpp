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
#include "InputClassifier.h"
#include "InputClassifierFuzzHelpers.h"
#include "tests/fuzzers/TestInputListenerLibrary/TestInputListener.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider tester(data, size);

    sp<TestInputListener> mTestListener = new TestInputListener();
    sp<InputClassifierInterface> mClassifier = new InputClassifier(mTestListener);

    // SendToNextStage_NotifyConfigurationChangedArgs
    NotifyConfigurationChangedArgs args(tester.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                        tester.ConsumeIntegral<nsecs_t>() /*eventTime*/);
    mClassifier->notifyConfigurationChanged(&args);
    NotifyConfigurationChangedArgs outArgs;
    mTestListener->assertNotifyConfigurationChangedWasCalled(&outArgs);

    // SendToNextStage_NotifyKeyArgs
    NotifyKeyArgs keyArgs(tester.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                          tester.ConsumeIntegral<nsecs_t>() /*eventTime*/,
                          tester.ConsumeIntegral<int32_t>() /*deviceId*/, AINPUT_SOURCE_KEYBOARD,
                          ADISPLAY_ID_DEFAULT, tester.ConsumeIntegral<uint32_t>() /*policyFlags*/,
                          AKEY_EVENT_ACTION_DOWN, tester.ConsumeIntegral<int32_t>() /*flags*/,
                          AKEYCODE_HOME, tester.ConsumeIntegral<int32_t>() /*scanCode*/, AMETA_NONE,
                          tester.ConsumeIntegral<nsecs_t>() /*downTime*/);

    mClassifier->notifyKey(&keyArgs);
    NotifyKeyArgs outKeyArgs;
    mTestListener->assertNotifyKeyWasCalled(&outKeyArgs);

    // SendToNextStage_NotifyMotionArgs
    NotifyMotionArgs motionArgs = generateBasicMotionArgs(&tester);
    mClassifier->notifyMotion(&motionArgs);
    NotifyMotionArgs motionOutArgs;
    mTestListener->assertNotifyMotionWasCalled(&motionOutArgs);

    // SendToNextStage_NotifySwitchArgs
    NotifySwitchArgs switchArgs(tester.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                tester.ConsumeIntegral<nsecs_t>() /*eventTime*/,
                                tester.ConsumeIntegral<uint32_t>() /*policyFlags*/,
                                tester.ConsumeIntegral<uint32_t>() /*switchValues*/,
                                tester.ConsumeIntegral<uint32_t>() /*switchMask*/);

    mClassifier->notifySwitch(&switchArgs);
    NotifySwitchArgs switchOutArgs;
    mTestListener->assertNotifySwitchWasCalled(&switchOutArgs);

    // SendToNextStage_NotifyDeviceResetArgs
    NotifyDeviceResetArgs resetArgs(tester.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                    tester.ConsumeIntegral<nsecs_t>() /*eventTime*/,
                                    tester.ConsumeIntegral<int32_t>() /*deviceId*/);

    mClassifier->notifyDeviceReset(&resetArgs);
    NotifyDeviceResetArgs resetOutArgs;
    mTestListener->assertNotifyDeviceResetWasCalled(&resetOutArgs);

    return 0;
}

} // namespace android