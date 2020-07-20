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

#include "TestInputListener.h"

namespace android {

// --- TestInputListener ---

TestInputListener::TestInputListener() {}

TestInputListener::~TestInputListener() {}

void TestInputListener::assertNotifyConfigurationChangedWasCalled(
        NotifyConfigurationChangedArgs* outEventArgs) {
    if (outEventArgs) {
        *outEventArgs = *mNotifyConfigurationChangedArgsQueue.begin();
    }
    mNotifyConfigurationChangedArgsQueue.erase(mNotifyConfigurationChangedArgsQueue.begin());
}

void TestInputListener::assertNotifyConfigurationChangedWasNotCalled() {
}

void TestInputListener::assertNotifyDeviceResetWasCalled(NotifyDeviceResetArgs* outEventArgs) {
    if (outEventArgs) {
        *outEventArgs = *mNotifyDeviceResetArgsQueue.begin();
    }
    mNotifyDeviceResetArgsQueue.erase(mNotifyDeviceResetArgsQueue.begin());
}

void TestInputListener::assertNotifyDeviceResetWasNotCalled() {
}

void TestInputListener::assertNotifyKeyWasCalled(NotifyKeyArgs* outEventArgs) {
    if (outEventArgs) {
        *outEventArgs = *mNotifyKeyArgsQueue.begin();
    }
    mNotifyKeyArgsQueue.erase(mNotifyKeyArgsQueue.begin());
}

void TestInputListener::assertNotifyKeyWasNotCalled() {
}

void TestInputListener::assertNotifyMotionWasCalled(NotifyMotionArgs* outEventArgs) {
    if (outEventArgs) {
        *outEventArgs = *mNotifyMotionArgsQueue.begin();
    }
    mNotifyMotionArgsQueue.erase(mNotifyMotionArgsQueue.begin());
}

void TestInputListener::assertNotifyMotionWasNotCalled() {
}

void TestInputListener::assertNotifySwitchWasCalled(NotifySwitchArgs* outEventArgs) {
    if (outEventArgs) {
        *outEventArgs = *mNotifySwitchArgsQueue.begin();
    }
    mNotifySwitchArgsQueue.erase(mNotifySwitchArgsQueue.begin());
}

void TestInputListener::notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) {
    mNotifyConfigurationChangedArgsQueue.push_back(*args);
}

void TestInputListener::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    mNotifyDeviceResetArgsQueue.push_back(*args);
}

void TestInputListener::notifyKey(const NotifyKeyArgs* args) {
    mNotifyKeyArgsQueue.push_back(*args);
}

void TestInputListener::notifyMotion(const NotifyMotionArgs* args) {
    mNotifyMotionArgsQueue.push_back(*args);
}

void TestInputListener::notifySwitch(const NotifySwitchArgs* args) {
    mNotifySwitchArgsQueue.push_back(*args);
}

} // namespace android
