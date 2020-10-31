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

#pragma once

#include "DumpstateClient.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android::os::bugreportz::test {

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

class Factory final : public IDumpstateFactory {
  public:
    sp<IDumpstate> GetService(const sp<android::IBinder::DeathRecipient>& recipient) override {
        recipient_ = recipient.get();
        return mds_;
    };

    sp<MockDumpstate> mds_  = new MockDumpstate;
    android::IBinder::DeathRecipient* recipient_{};
};

class TestableDumpstateClient {
  public:
    Status StartBugreport(bool show_progress) {
        ALOGW("TestableDumpstateClient StartBugreport");
        return mClient->StartBugreport(show_progress);
    }

    void ExpectStartBugreport() const {
        using ::testing::_;
        auto ds = sp<MockDumpstate>(mFactory.mds_);
        EXPECT_CALL(*ds, startBugreport(_,_,_,_,_,_,_)).Times(1);
    }

  private:
    test::Factory mFactory;
    DumpstateClient* mClient = new DumpstateClient(dup(STDOUT_FILENO), mFactory);
};

} // namespace android::os::bugreport
