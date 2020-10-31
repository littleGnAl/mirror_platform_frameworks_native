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

#ifndef FRAMEWORK_NATIVE_CMD_TESTABLE_DUMPSTATE_CLIENT_H_
#define FRAMEWORK_NATIVE_CMD_TESTABLE_DUMPSTATE_CLIENT_H_

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
    Factory() : Factory(sp<MockDumpstate>::make()) {};
    explicit Factory(sp<MockDumpstate> md) :mds_(md), recipient_(nullptr) {};

    sp<IDumpstate> GetService(const sp<android::IBinder::DeathRecipient>& recipient) override {
        recipient_ = recipient.get();
        return mds_;
    };

  private:
    sp<MockDumpstate> mds_;
    android::IBinder::DeathRecipient* recipient_;
};

class TestableDumpstateClient {
  public:
    TestableDumpstateClient(int fd, sp<MockDumpstate> md)
        : mDumpstate(md),
          mFactory(std::make_unique<Factory>(md)),
          mClient(std::make_unique<DumpstateClient>(fd, *mFactory)) {
    }

    Status StartBugreport(bool show_progress) {
        return mClient->StartBugreport(show_progress);
    }

  private:
    sp<MockDumpstate> mDumpstate;
    unique_ptr<Factory> mFactory;
    unique_ptr<DumpstateClient> mClient;
};

} // namespace android::os::bugreport

#endif  // FRAMEWORK_NATIVE_CMD_TESTABLE_DUMPSTATE_CLIENT_H_
