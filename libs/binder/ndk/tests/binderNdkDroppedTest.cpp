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

#include <gtest/gtest.h>

#include <aidl/BnBinderNdkDroppedTest.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <atomic>

#include <sys/prctl.h>

static const char* kServiceName = "IBinderNdkDroppedTest";
static constexpr size_t kSends = 10;

class MyBinderNdkDroppedTest : public aidl::BnBinderNdkDroppedTest {
   public:
    std::atomic<size_t> sendCount = 0;

    ::ndk::ScopedAStatus send(const ::ndk::SpAIBinder& binder) {
        sendCount++;
        EXPECT_NE(binder.get(), nullptr);

        std::cout << "server got binder i " << sendCount << std::endl;
        if (sendCount < 5) sleep(1);

        return ::ndk::ScopedAStatus::ok();
    }
};

void client() {
    ndk::SpAIBinder binder = ndk::SpAIBinder(AServiceManager_getService(kServiceName));
    auto service = aidl::IBinderNdkDroppedTest::fromBinder(binder);
    for (size_t i = 0; i < kSends; i++) {
        std::cout << "client sending binder i " << i << std::endl;
        // this could be any binder, constructing this one out of convenience
        std::shared_ptr<aidl::IBinderNdkDroppedTest> server =
                ndk::SharedRefBase::make<MyBinderNdkDroppedTest>();
        service->send(server->asBinder());
    }
    std::cout << "client exiting" << std::endl;

    // force exit, no cleanup
    _exit(0);
}

TEST(BinderNdkDroppedTest, Wheeeeeeeeeeeeeeeeeeeee) {
    std::shared_ptr<MyBinderNdkDroppedTest> server =
            ndk::SharedRefBase::make<MyBinderNdkDroppedTest>();
    AServiceManager_addService(server->asBinder().get(), kServiceName);

    while (server->sendCount < kSends) {
        std::cout << "checking sends: " << server->sendCount << "/" << kSends << std::endl;
        sleep(1);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        // child process
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        client();

        exit(1);  // should not reach
    }

    ABinderProcess_setThreadPoolMaxThreadCount(1);
    ABinderProcess_startThreadPool();

    return RUN_ALL_TESTS();
}
