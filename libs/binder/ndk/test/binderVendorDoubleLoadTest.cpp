/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <binder/ProcessState.h>
#include <gtest/gtest.h>

using ::android::ProcessState;

// For brevity:
// 'cpp' to refer to libbinder
// 'ndk' to refer to libbinder_ndk

TEST(DoubleBinder, CppIsDevBinder) {
    std::string driver = ProcessState::self()->getDriverName().c_str();
    ASSERT_EQ("/dev/binder", driver);
}

// TODO: assert where we are loading libbinder from (should be vendor)
// TODO: assert we are loading libbinder_ndk from system (and also libbinder)
// TODO: test that we can make calls simultaneously via libbinder and via
//     libbinder_ndk (the motivation is for service registration to go over
//     libbinder_ndk but vnd<->vnd comms to go over libbinder).

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Explicitly instantiated with the same driver that system would use.
    ProcessState::initWithDriver("/dev/binder");
    ProcessState::self()->startThreadPool();

    return RUN_ALL_TESTS();
}
