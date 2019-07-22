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

#include <BnBinderVendorDoubleLoadTest.h>
#include <aidl/BnBinderVendorDoubleLoadTest.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/binder_stability.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/Stability.h>
#include <binder/Status.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>
#include <fstream>

using namespace android;
using ::android::base::EndsWith;
using ::android::base::GetProperty;
using ::android::base::Split;
using ::android::binder::Status;
using ::android::internal::Stability;
using ::ndk::ScopedAStatus;
using ::ndk::SharedRefBase;
using ::ndk::SpAIBinder;

static const std::string kLocalNdkServerName = "NdkServer-local-IBinderVendorDoubleLoadTest";
static const std::string kRemoteNdkServerName = "NdkServer-remote-IBinderVendorDoubleLoadTest";

class NdkServer : public aidl::BnBinderVendorDoubleLoadTest {
    ScopedAStatus RepeatString(const std::string& in, std::string* out) override {
        *out = in;
        return ScopedAStatus::ok();
    }
};
class CppServer : public BnBinderVendorDoubleLoadTest {
    Status RepeatString(const std::string& in, std::string* out) override {
        *out = in;
        return Status::ok();
    }
};

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
    std::set<std::string> files = mappedFiles();

    std::string vndkLoc = GetProperty("ro.vndk.version", "ERROR");

    ASSERT_TRUE(files.find("/system/lib64/libbinder_ndk.so") != files.end() ||
                files.find("/system/lib/libbinder_ndk.so") != files.end());
    ASSERT_TRUE(files.find("/system/lib64/libbinder.so") != files.end() ||
                files.find("/system/lib/libbinder.so") != files.end());
    ASSERT_TRUE(files.find("/system/lib64/vndk-" + vndkLoc + "/libbinder.so") != files.end() ||
                files.find("/system/lib/vndk-" + vndkLoc + "/libbinder.so") != files.end())
            << vndkLoc;

    ASSERT_FALSE(files.find("/dev/vndbinder") != files.end());
}

TEST(DoubleBinder, VendorCppCantCallIntoSystem) {
    Vector<String16> services = defaultServiceManager()->listServices();
    EXPECT_TRUE(services.empty());
}

TEST(DoubleBinder, VendorCppCantRegisterService) {
    sp<CppServer> cppServer = new CppServer;
    status_t status = defaultServiceManager()->addService(String16("anything"), cppServer);
    EXPECT_EQ(status, OK);  // FIXME
}

TEST(DoubleBinder, CppVendorCantManuallyMarkVintfStability) {
    // this test also implies that stability logic is turned on in vendor
    ASSERT_DEATH(
            {
                sp<IBinder> binder = new CppServer();
                Stability::markVndk(binder.get());
            },
            "Should not mark objectts");
}

TEST(DoubleBinder, NdkVendorCantManuallyMarkVintfStability) {
    // this test also implies that stability logic is turned on in vendor
    ASSERT_DEATH(
            {
                std::shared_ptr<NdkServer> ndkServer = SharedRefBase::make<NdkServer>();
                AIBinder_markVintfStability(ndkServer->asBinder().get());
            },
            "Should not mark objectts");
}

TEST(DoubleBinder, CallIntoNdk) {
    for (const std::string& serviceName : {kLocalNdkServerName, kRemoteNdkServerName}) {
        // Calling from NDK is okay
        {
            SpAIBinder binder = SpAIBinder(AServiceManager_checkService(serviceName.c_str()));
            ASSERT_NE(nullptr, binder.get()) << serviceName;
            EXPECT_EQ(STATUS_OK, AIBinder_ping(binder.get())) << serviceName;

            std::shared_ptr<aidl::IBinderVendorDoubleLoadTest> server =
                    aidl::IBinderVendorDoubleLoadTest::fromBinder(binder);

            ASSERT_NE(nullptr, server.get()) << serviceName;

            std::string outString;
            EXPECT_TRUE(server->RepeatString("foo", &outString).isOk()) << serviceName;
            EXPECT_EQ("foo", outString) << serviceName;
        }

        // Calling from SDK fails
        {
            sp<IBinder> binder =
                    defaultServiceManager()->checkService(String16(serviceName.c_str()));
            ASSERT_EQ(nullptr, binder.get()) << serviceName;
        }
    }
}

void initDrivers() {
    // Explicitly instantiated with the same driver that system would use.
    // __ANDROID_VNDK__ right now uses /dev/vndbinder by default.
    ProcessState::initWithDriver("/dev/binder");
    ProcessState::self()->startThreadPool();
    ABinderProcess_startThreadPool();
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        // child process

        prctl(PR_SET_PDEATHSIG, SIGHUP);

        initDrivers();

        // REMOTE SERVERS
        std::shared_ptr<NdkServer> ndkServer = SharedRefBase::make<NdkServer>();
        AServiceManager_addService(ndkServer->asBinder().get(), kRemoteNdkServerName.c_str());

        // OR sleep forever or whatever, it doesn't matter
        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }

    sleep(1);

    initDrivers();

    // LOCAL SERVERS
    std::shared_ptr<NdkServer> ndkServer = SharedRefBase::make<NdkServer>();
    AServiceManager_addService(ndkServer->asBinder().get(), kLocalNdkServerName.c_str());

    return RUN_ALL_TESTS();
}
