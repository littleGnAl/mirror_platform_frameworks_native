/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "Lshal"
#include <android-base/logging.h>

#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <android/hardware/tests/baz/1.0/IQuux.h>
#include <hidl/HidlTransportSupport.h>

#include "MockableServiceManager.h"
#include "Lshal.h"

#define NELEMS(array)   static_cast<int>(sizeof(array) / sizeof(array[0]))

using namespace testing;

using ::android::hidl::base::V1_0::IBase;
using ::android::hidl::manager::V1_0::IServiceManager;
using ::android::hardware::hidl_string;


namespace android {
namespace hardware {
namespace tests {
namespace baz {
namespace V1_0 {
namespace implementation {
struct Quux : android::hardware::tests::baz::V1_0::IQuux {
    ::android::hardware::Return<void> debug(const hidl_handle& hh, const hidl_vec<hidl_string>& options) override {
        const native_handle_t *handle = hh.getNativeHandle();
        if (handle->numFds < 1) {
            return Void();
        }
        int fd = handle->data[0];
        std::string content{descriptor};
        for (const auto &option : options) {
            content += "\n";
            content += option.c_str();
        }
        ssize_t written = write(fd, content.c_str(), content.size());
        if (written != (ssize_t)content.size()) {
            LOG(WARNING) << "SERVER(Quux) debug writes " << written << " bytes < "
                    << content.size() << " bytes, errno = " << errno;
        }
        return Void();
    }
};

} // namespace implementation
} // namespace V1_0
} // namespace baz
} // namespace tests
} // namespace hardware

namespace lshal {

class MockServiceManager : public MockableServiceManager {
public:
    ~MockServiceManager() = default;
    MOCK_METHOD1(list, ::android::hardware::Return<void>(IServiceManager::list_cb));
    MOCK_METHOD1(debugDump, ::android::hardware::Return<void>(IServiceManager::debugDump_cb));
    MOCK_METHOD2(get, ::android::hardware::Return<sp<IBase>>(const hidl_string&, const hidl_string&));
};

class LshalTest : public ::testing::Test {
public:
    void SetUp() override {
        using ::android::hardware::tests::baz::V1_0::IQuux;
        using ::android::hardware::tests::baz::V1_0::implementation::Quux;

        err.str("");
        out.str("");
        serviceManager = new testing::NiceMock<MockServiceManager>();
        ON_CALL(*serviceManager, get(_, _)).WillByDefault(Invoke(
            [](const auto &iface, const auto &inst) -> ::android::hardware::Return<sp<IBase>> {
                if (iface == IQuux::descriptor && inst == "default")
                    return new Quux();
                return nullptr;
            }));
    }
    void TearDown() override {}

    std::stringstream err;
    std::stringstream out;
    sp<MockServiceManager> serviceManager;
};

TEST_F(LshalTest, Debug) {
    const char *args[] = {
        "lshal", "debug", "android.hardware.tests.baz@1.0::IQuux/default", "foo", "bar"
    };
    EXPECT_EQ(0u, Lshal(out, err, serviceManager, serviceManager)
            .main({NELEMS(args), const_cast<char **>(args)}));
    EXPECT_THAT(out.str(), StrEq("android.hardware.tests.baz@1.0::IQuux\nfoo\nbar"));
    EXPECT_THAT(err.str(), IsEmpty());
}

TEST_F(LshalTest, Debgu2) {
    const char *args[] = {
        "lshal", "debug", "android.hardware.tests.baz@1.0::IQuux", "baz", "quux"
    };
    EXPECT_EQ(0u, Lshal(out, err, serviceManager, serviceManager)
            .main({NELEMS(args), const_cast<char **>(args)}));
    EXPECT_THAT(out.str(), StrEq("android.hardware.tests.baz@1.0::IQuux\nbaz\nquux"));
    EXPECT_THAT(err.str(), IsEmpty());
}

} // namespace lshal
} // namespace android

int main(int argc, char **argv) {
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
