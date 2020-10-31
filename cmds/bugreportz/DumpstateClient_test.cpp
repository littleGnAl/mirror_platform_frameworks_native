// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "DumpstateClient.h"
#include "TestableDumpstateClient.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include <memory>

namespace android::os::bugreportz {

class DumpstateClientTest : public ::testing::Test {
  public:
    DumpstateClientTest() {
        ALOGW("DumpstateClientTest ctor");
    }

    bool initCheck() const {
        ALOGW("initCheck");
        bool hasInit = nullptr != client_.GetService();
//        ALOGW("client_->ds_ %p", client_.GetService());
        return hasInit;
    };

    // test::Factory* factory_;
    test::TestableDumpstateClient client_;
};

// TODO: replace the poc case with client tests
TEST_F(DumpstateClientTest, CanCancel) {
    ASSERT_TRUE(initCheck());

    // sp<MockDumpstate> mds = static_cast<MockDumpstate*>(client_->ds_.get());
     sp<test::MockDumpstate> ds = client_.GetFactory()->mds_;
    ALOGW("expect cancel");
    EXPECT_CALL(*ds, cancelBugreport()).Times(1);
    // EXPECT_CALL(*mds, cancelBugreport()).Times(1);

//    EXPECT_EQ(cancel(), NO_ERROR);
//    client_.GetService()->cancelBugreport();
    client_.cancel();
}

} // namespace android::os::bugreportz
