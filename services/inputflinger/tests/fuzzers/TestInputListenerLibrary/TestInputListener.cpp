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

#define GREPFORME "TestInputListenerGrepStringSinceNoAsserts"

namespace android {

// --- TestInputListener ---

TestInputListener::TestInputListener() {}

TestInputListener::~TestInputListener() {}

void TestInputListener::assertNotifyConfigurationChangedWasCalled(
        NotifyConfigurationChangedArgs* outEventArgs) {
    if (mNotifyConfigurationChangedArgsQueue.empty()) {
        printf("assertNotifyConfigurationChangedWasCalled should NOT have been empty %s\n",
               GREPFORME);
    }
    if (outEventArgs) {
        *outEventArgs = *mNotifyConfigurationChangedArgsQueue.begin();
    }
    mNotifyConfigurationChangedArgsQueue.erase(mNotifyConfigurationChangedArgsQueue.begin());
}

void TestInputListener::assertNotifyConfigurationChangedWasNotCalled() {
    if (!mNotifyConfigurationChangedArgsQueue.empty()) {
        printf("assertNotifyConfigurationChangedWasNotCalled should be empthy %s\n", GREPFORME);
    }
}

void TestInputListener::assertNotifyDeviceResetWasCalled(NotifyDeviceResetArgs* outEventArgs) {
    if (mNotifyDeviceResetArgsQueue.empty()) {
        printf("assertNotifyDeviceResetWasCalled should NOT be empty %s\n", GREPFORME);
    }
    if (outEventArgs) {
        *outEventArgs = *mNotifyDeviceResetArgsQueue.begin();
    }
    mNotifyDeviceResetArgsQueue.erase(mNotifyDeviceResetArgsQueue.begin());
}

void TestInputListener::assertNotifyDeviceResetWasNotCalled() {
    if (!mNotifyDeviceResetArgsQueue.empty()) {
        printf("assertNotifyDeviceResetWasNotCalled should NOT have been empty %s\n", GREPFORME);
    }
}

void TestInputListener::assertNotifyKeyWasCalled(NotifyKeyArgs* outEventArgs) {
    if (mNotifyKeyArgsQueue.empty()) {
        printf("assertNotifyKeyWasCalled should NOT have been empty %s\n", GREPFORME);
    }
    if (outEventArgs) {
        *outEventArgs = *mNotifyKeyArgsQueue.begin();
    }
    mNotifyKeyArgsQueue.erase(mNotifyKeyArgsQueue.begin());
}

void TestInputListener::assertNotifyKeyWasNotCalled() {
    if (!mNotifyKeyArgsQueue.empty()) {
        printf("assertNotifyKeyWasNotCalled should have been empty %s\n", GREPFORME);
    }
}

void TestInputListener::assertNotifyMotionWasCalled(NotifyMotionArgs* outEventArgs) {
    if (mNotifyMotionArgsQueue.empty()) {
        printf("assertNotifyMotionWasCalled should NOT have been empty %s\n", GREPFORME);
    }
    if (outEventArgs) {
        *outEventArgs = *mNotifyMotionArgsQueue.begin();
    }
    mNotifyMotionArgsQueue.erase(mNotifyMotionArgsQueue.begin());
}

void TestInputListener::assertNotifyMotionWasNotCalled() {
    if (!mNotifyMotionArgsQueue.empty()) {
        printf("assertNotifyMotionWasNotCalled queue was NOT EMPTY %s\n", GREPFORME);
    }
}

void TestInputListener::assertNotifySwitchWasCalled(NotifySwitchArgs* outEventArgs) {
    if (mNotifySwitchArgsQueue.empty()) {
        printf("assertNotifySwitchWasCalled should NOT have been empty %s\n", GREPFORME);
    }
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
