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

#include <android-base/strings.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>

#include <fstream>
#include "android/binder_ibinder.h"

using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::OK;
using ::android::ProcessState;
using ::android::sp;
using ::android::String16;
using ::android::base::EndsWith;
using ::android::base::Split;

static std::set<std::string> mappedFiles() {
    std::set<std::string> files;

    std::ifstream ifs("/proc/self/maps");
    for (std::string line; std::getline(ifs, line);) {
        auto elms = Split(line, " ");
        if (!elms.empty()) {
            files.insert(elms[elms.size() - 1]);
        }
    }

    return files;
}

TEST(DoubleBinder, ExpectedFilesOpen) {
    auto files = mappedFiles();
    ASSERT_TRUE(files.find("/system/lib64/libbinder_ndk.so") != files.end() ||
                files.find("/system/lib/libbinder_ndk.so") != files.end());
    ASSERT_TRUE(files.find("/system/lib64/libbinder.so") != files.end() ||
                files.find("/system/lib/libbinder.so") != files.end());
    ASSERT_TRUE(files.find("/system/lib64/vndk-R/libbinder.so") != files.end() ||
                files.find("/system/lib/vndk-R/libbinder.so") != files.end());

    ASSERT_FALSE(files.find("/dev/vndbinder") != files.end());
}

TEST(DoubleBinder, MakeSimultaneousCalls) {
    const char* kAnyOldService = "SurfaceFlinger";

    for (size_t i = 0; i < 100; i++) {
        {
            // stability/permissions should ensure that this fails, but it will succeed
            // as root.
            AIBinder* binder = AServiceManager_getService(kAnyOldService);
            EXPECT_EQ(STATUS_OK, AIBinder_ping(binder));
            AIBinder_decStrong(binder);
        }

        {
            // talking to a system binder, but we should test talking to a
            // vendor binder instead in order to avoid hitting stability
            // problems in the future
            sp<IBinder> binder = defaultServiceManager()->getService(String16(kAnyOldService));
            EXPECT_EQ(OK, binder->pingBinder());
        }
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Explicitly instantiated with the same driver that system would use.
    // __ANDROID_VNDK__ right now uses /dev/vndbinder by default.
    ProcessState::initWithDriver("/dev/binder");
    ProcessState::self()->startThreadPool();

    ABinderProcess_startThreadPool();

    return RUN_ALL_TESTS();
}
