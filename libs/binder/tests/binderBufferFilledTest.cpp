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

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>

#include "BnBinderBufferFilledTest.h"

using android::IPCThreadState;
using android::OK;
using android::ProcessState;
using android::String16;
using android::binder::Status;
using android::sp;
using android::waitForService;
using android::IBinder;

static const String16 kServiceName = String16("IBinderBufferFilledTest");

class MyBinderBufferFilledTest : public BnBinderBufferFilledTest {
public:
    Status block() override {
        // pick your poison
        std::mutex m;
        m.lock();
        return Status::ok();
    }
    Status doNothing(const std::string& wasteSpace) override {
        (void) wasteSpace;
        return Status::ok();
    }
};

TEST(BinderBufferFilled, Wheeeeeeeeeeeeeeeeeeeee) {
    sp<IBinderBufferFilledTest> server = waitForService<IBinderBufferFilledTest>(kServiceName);
    ASSERT_NE(nullptr, server);

    ASSERT_TRUE(server->block().isOk());

    std::string a_big_string = std::string(30241, 'a');  // a pretty big number

    while (true) {
        Status s = server->doNothing(a_big_string);
        ASSERT_TRUE(s.isOk()) << s.toString8();
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        // child process
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        sp<IBinder> server = new MyBinderBufferFilledTest;
        android::defaultServiceManager()->addService(kServiceName, server);

        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }

    ProcessState::self()->setThreadPoolMaxThreadCount(1);
    ProcessState::self()->startThreadPool();

    return RUN_ALL_TESTS();
}
