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

#include <aidl/BnBinderRustNDKInteropTest.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/Status.h>
#include <gtest/gtest.h>

using namespace android;
using ::ndk::ScopedAStatus;
using ::ndk::SharedRefBase;
using ::ndk::SpAIBinder;

static const char* kNdkServerName = "NdkServer-BinderRustNDKInteropTest";
static const char* kRustServerName = "RustServer-BinderRustNDKInteropTest";

extern "C" {
int rust_call_ndk(const char* service_name);
int rust_start_service(const char* service_name);
}

class NdkServer : public aidl::BnBinderRustNDKInteropTest {
    ScopedAStatus Echo(const std::string& in, std::string* out) override {
        *out = in;
        return ScopedAStatus::ok();
    }
};

TEST(RustNDKInterop, RustCanCallNDK) {
    ASSERT_EQ(STATUS_OK, rust_call_ndk(kNdkServerName));
}

TEST(RustNDKInterop, NdkCanCallRust) {
    ASSERT_EQ(STATUS_OK, rust_start_service(kRustServerName));

    SpAIBinder binder = SpAIBinder(AServiceManager_checkService(kRustServerName));
    ASSERT_NE(nullptr, binder.get());
    EXPECT_EQ(STATUS_OK, AIBinder_ping(binder.get()));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // so we can host a client and service concurrently
    ABinderProcess_setThreadPoolMaxThreadCount(1);
    ABinderProcess_startThreadPool();

    std::shared_ptr<NdkServer> ndkServer = SharedRefBase::make<NdkServer>();
    AServiceManager_addService(ndkServer->asBinder().get(), kNdkServerName);

    return RUN_ALL_TESTS();
}
