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
    FuzzedDataProvider fdp(data, size);

    sp<TestInputListener> mTestListener = new TestInputListener();
    sp<InputClassifierInterface> mClassifier = new InputClassifier(mTestListener);

    // SendToNextStage_NotifyConfigurationChangedArgs
    NotifyConfigurationChangedArgs args(fdp.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                        fdp.ConsumeIntegral<nsecs_t>() /*eventTime*/);
    mClassifier->notifyConfigurationChanged(&args);
    NotifyConfigurationChangedArgs outArgs;
    mTestListener->assertNotifyConfigurationChangedWasCalled(&outArgs);

    // SendToNextStage_NotifyKeyArgs
    NotifyKeyArgs keyArgs(fdp.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                          fdp.ConsumeIntegral<nsecs_t>() /*eventTime*/,
                          fdp.ConsumeIntegral<int32_t>() /*deviceId*/, AINPUT_SOURCE_KEYBOARD,
                          ADISPLAY_ID_DEFAULT, fdp.ConsumeIntegral<uint32_t>() /*policyFlags*/,
                          AKEY_EVENT_ACTION_DOWN, fdp.ConsumeIntegral<int32_t>() /*flags*/,
                          AKEYCODE_HOME, fdp.ConsumeIntegral<int32_t>() /*scanCode*/, AMETA_NONE,
                          fdp.ConsumeIntegral<nsecs_t>() /*downTime*/);

    mClassifier->notifyKey(&keyArgs);
    NotifyKeyArgs outKeyArgs;
    mTestListener->assertNotifyKeyWasCalled(&outKeyArgs);

    // SendToNextStage_NotifyMotionArgs
    NotifyMotionArgs motionArgs = generateFuzzedMotionArgs(&fdp);
    mClassifier->notifyMotion(&motionArgs);
    NotifyMotionArgs motionOutArgs;
    mTestListener->assertNotifyMotionWasCalled(&motionOutArgs);

    // SendToNextStage_NotifySwitchArgs
    NotifySwitchArgs switchArgs(fdp.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                fdp.ConsumeIntegral<nsecs_t>() /*eventTime*/,
                                fdp.ConsumeIntegral<uint32_t>() /*policyFlags*/,
                                fdp.ConsumeIntegral<uint32_t>() /*switchValues*/,
                                fdp.ConsumeIntegral<uint32_t>() /*switchMask*/);

    mClassifier->notifySwitch(&switchArgs);
    NotifySwitchArgs switchOutArgs;
    mTestListener->assertNotifySwitchWasCalled(&switchOutArgs);

    // SendToNextStage_NotifyDeviceResetArgs
    NotifyDeviceResetArgs resetArgs(fdp.ConsumeIntegral<uint32_t>() /*sequenceNum*/,
                                    fdp.ConsumeIntegral<nsecs_t>() /*eventTime*/,
                                    fdp.ConsumeIntegral<int32_t>() /*deviceId*/);

    mClassifier->notifyDeviceReset(&resetArgs);
    NotifyDeviceResetArgs resetOutArgs;
    mTestListener->assertNotifyDeviceResetWasCalled(&resetOutArgs);

    return 0;
}

} // namespace android