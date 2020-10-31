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

#include <android-base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include <memory>

class MockDumpstate : public android::os::IDumpstate {
  public:
    MOCK_METHOD(android::binder::Status, startBugreport,
                ((int32_t callingUid), (const std::string& callingPackage),
                 (android::base::unique_fd bugreportFd), (android::base::unique_fd screenshotFd),
                 (int32_t bugreportMode),
                 (const android::sp<android::os::IDumpstateListener>& listener),
                 (bool isScreenshotRequested)),
                (override));
    MOCK_METHOD(android::binder::Status, cancelBugreport, (), (override));
    MOCK_METHOD(android::IBinder*, onAsBinder, (), (override));
};

class MockDumpstateFactory : public IDumpstateFactory {
  public:
    sp<IDumpstate> CreateService(sp<android::IBinder::DeathRecipient> recipient) override {
        sp<MockDumpstate> mds = new MockDumpstate();
        recipient_ = recipient;
        return mds;
    };
    sp<android::IBinder::DeathRecipient> recipient_;
};

class DumpstateClientTest : public ::testing::Test {
  public:
    DumpstateClientTest()
        : factory_(new MockDumpstateFactory()),
          client_(new DumpstateClient(dup(STDOUT_FILENO),
                                      unique_ptr<MockDumpstateFactory>(factory_))){};

  protected:
    MockDumpstateFactory* factory_;
    std::shared_ptr<DumpstateClient> client_;
};

// TODO: replace the poc case with client tests
TEST_F(DumpstateClientTest, CanCancel) {
    ASSERT_THAT(client_->ds_.get(), testing::NotNull());
    sp<MockDumpstate> mds = static_cast<MockDumpstate*>(client_->ds_.get());
    EXPECT_CALL(*mds, cancelBugreport()).Times(1);

    client_->ds_->cancelBugreport();
}
