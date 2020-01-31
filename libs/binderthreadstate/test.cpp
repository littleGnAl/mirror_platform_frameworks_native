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

#include <android-base/logging.h>
#include <binderthreadstateutilstest/1.0/IHidlStuff.h>
#include <BnAidlStuff.h>
#include <binderthreadstate/CallerUtils.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>
#include <hidl/HidlTransportSupport.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

using android::BinderCallType;
using android::OK;
using android::String16;
using android::binder::Status;
using android::defaultServiceManager;
using android::getCurrentServingCall;
using android::hardware::Return;
using android::sp;
using binderthreadstateutilstest::V1_0::IHidlStuff;
using android::getService;

// only AIDL since HIDL services are already namespaced
constexpr char kAidlName[] = "aidl-testing-service";

class HidlServer : public IHidlStuff {
    Return<void> callLocal() {
        CHECK(BinderCallType::NONE == getCurrentServingCall());
        return android::hardware::Status::ok();
    }
    Return<void> call(int32_t idx) {
        CHECK(BinderCallType::HWBINDER == getCurrentServingCall());
        if (idx > 0) {
            sp<IAidlStuff> stuff;
            CHECK(OK == android::getService<IAidlStuff>(String16(kAidlName), &stuff));
            CHECK(stuff->call(idx - 1).isOk());
        }
        CHECK(BinderCallType::HWBINDER == getCurrentServingCall());
        return android::hardware::Status::ok();
    }
};
class AidlServer : public BnAidlStuff {
    Status callLocal() {
        CHECK(BinderCallType::NONE == getCurrentServingCall());
        return Status::ok();
    }
    Status call(int32_t idx) {
        CHECK(BinderCallType::BINDER == getCurrentServingCall());
        if (idx > 0) {
            auto stuff = IHidlStuff::getService();
            CHECK(stuff->call(idx-1).isOk());
        }
        CHECK(BinderCallType::BINDER == getCurrentServingCall());
        return Status::ok();
    }
};

TEST(BinderThreadState, LocalHidlCall) {
    sp<IHidlStuff> server = new HidlServer;
    EXPECT_TRUE(server->callLocal().isOk());
}

TEST(BinderThreadState, LocalAidlCall) {
    sp<IAidlStuff> server = new AidlServer;
    EXPECT_TRUE(server->callLocal().isOk());
}

TEST(BindThreadState, RemoteHidlCall) {
    auto stuff = IHidlStuff::getService();
    ASSERT_NE(nullptr, stuff);
    ASSERT_TRUE(stuff->call(0).isOk());
}
TEST(BindThreadState, RemoteAidlCall) {
    sp<IAidlStuff> stuff;
    ASSERT_EQ(OK, android::getService<IAidlStuff>(String16(kAidlName), &stuff));
    ASSERT_NE(nullptr, stuff);
    ASSERT_TRUE(stuff->call(0).isOk());
}

TEST(BindThreadState, RemoteNestedStartHidlCall) {
    auto stuff = IHidlStuff::getService();
    ASSERT_NE(nullptr, stuff);
    ASSERT_TRUE(stuff->call(1).isOk());
}
TEST(BindThreadState, RemoteNestedStartAidlCall) {
    sp<IAidlStuff> stuff;
    ASSERT_EQ(OK, android::getService<IAidlStuff>(String16(kAidlName), &stuff));
    ASSERT_NE(nullptr, stuff);
    EXPECT_TRUE(stuff->call(1).isOk());
}

int hidlServer() {
    setenv("TREBLE_TESTING_OVERRIDE", "true", true);
    android::hardware::configureRpcThreadpool(1, true /*callerWillJoin*/);
    sp<IHidlStuff> server = new HidlServer;
    CHECK(OK == server->registerAsService());
    android::hardware::joinRpcThreadpool();
    return EXIT_FAILURE;
}

int aidlServer() {
    using android::IPCThreadState;
    using android::ProcessState;
    ProcessState::self()->setThreadPoolMaxThreadCount(0);
    sp<AidlServer> server = new AidlServer;
    CHECK(OK == defaultServiceManager()->addService(String16(kAidlName), server));
    IPCThreadState::self()->joinThreadPool();
    return EXIT_FAILURE;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    setenv("TREBLE_TESTING_OVERRIDE", "true", true);
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return hidlServer();
    }
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return aidlServer();
    }

    // FIXME: wait for services to start
    sleep(1);

    return RUN_ALL_TESTS();
}
