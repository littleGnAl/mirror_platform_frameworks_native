/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "bugreportz.h"

#include <android-base/stringprintf.h>
#include <cutils/android_filesystem_config.h>
#include <gmock/gmock.h>
#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include <string>

namespace android::os::bugreportz {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Test;
using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStdout;
using ::android::base::unique_fd;
using ::android::binder::Status;
using ::android::os::IDumpstateListener;
using ::android::os::bugreportz::DumpstateClient;

class MockBinder : public BBinder {
  public:
    MOCK_METHOD(status_t, linkToDeath,
                (const sp<DeathRecipient>& recipient, void* cookie, uint32_t flags), (override));
    MOCK_METHOD(status_t, unlinkToDeath,
                (const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
                 wp<DeathRecipient>* outRecipient),
                (override));
    MOCK_METHOD(status_t, pingBinder, (), (override));
};

class MockDumpstate : public android::os::IDumpstate {
  public:
    virtual Status startBugreport(
        int32_t callingUid, const std::string& callingPackage,
        unique_fd bugreportFd, unique_fd screenshotFd, int32_t bugreportMode,
        const sp<IDumpstateListener>& listener, bool isScreenshotRequested) override {
            EXPECT_EQ(callingUid, AID_SHELL);
            EXPECT_EQ(callingPackage, "");
            EXPECT_TRUE(bugreportFd.ok());
            EXPECT_TRUE(screenshotFd.ok());
            EXPECT_TRUE(listener);
            EXPECT_EQ(bugreportMode, IDumpstate::BUGREPORT_MODE_DEFAULT);
            EXPECT_FALSE(isScreenshotRequested);
            return startBugreport();
    };
    MOCK_METHOD(Status, startBugreport, (), ());
    MOCK_METHOD(Status, cancelBugreport, (), (override));
    MOCK_METHOD(IBinder*, onAsBinder, (), (override));
};

class BugreportzTest : public Test {
  public:
    // Creates the pipe used to communicate with bugreportz()
    void SetUp() {
        int fds[2];
        ASSERT_EQ(0, pipe(fds));
        read_fd_ = fds[0];
        write_fd_ = fds[1];
    }

    // Closes the pipe FDs.
    // If a FD is closed manually during a test, set it to -1 to prevent TearDown() trying to close
    // it again.
    void TearDown() {
        for (int fd : {read_fd_, write_fd_}) {
            if (fd >= 0) {
                close(fd);
            }
        }
    }

    // Emulates dumpstate output by writing to the socket passed to bugreportz()
    void WriteToSocket(const std::string& data) {
        if (write_fd_ < 0) {
            ADD_FAILURE() << "cannot write '" << data << "' because socket is already closed";
            return;
        }
        int expected = data.length();
        int actual = write(write_fd_, data.data(), data.length());
        ASSERT_EQ(expected, actual) << "wrong number of bytes written to socket";
    }

    void AssertStdoutEquals(const std::string& expected) {
        ASSERT_THAT(stdout_, StrEq(expected)) << "wrong stdout output";
    }

    // Calls bugreportz() using the internal pipe.
    //
    // Tests must call WriteToSocket() to set what's written prior to calling it, since the writing
    // end of the pipe will be closed before calling bugreportz() (otherwise that function would
    // hang).
    void BugreportzStream() {
        close(write_fd_);
        write_fd_ = -1;

        CaptureStdout();
        int status = bugreportz_stream(read_fd_);

        close(read_fd_);
        read_fd_ = -1;
        stdout_ = GetCapturedStdout();

        ASSERT_EQ(0, status) << "bugrepotz_stream() call failed (stdout: " << stdout_ << ")";
    }

  private:
    int read_fd_;
    int write_fd_;
    std::string stdout_;
};

// Tests 'bugreportz -s' - just echo data
TEST_F(BugreportzTest, WithStream) {
    char emptyZip[] = "\x50\x4B\x05\x06\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    std::string data(emptyZip);
    WriteToSocket(data);

    BugreportzStream();

    AssertStdoutEquals(data);
}

class DumpstateClientTest : public Test {
  public:
    void SetUp() {
        binder_ = sp<MockBinder>::make();
        ds_ = sp<MockDumpstate>::make();
        client_ = sp<DumpstateClient>::make(STDOUT_FILENO, ds_);
        ON_CALL(*ds_, onAsBinder).WillByDefault(Return(binder_.get()));
    }

    void Bugreportz(bool show_progress, const sp<DumpstateClient>& client) {
        CaptureStdout();
        int status = ::bugreportz(show_progress, client);

        stdout_ = GetCapturedStdout();
        ASSERT_EQ(0, status) << "bugrepotz() call failed (stdout: " << stdout_ << ")";
    }

    void AssertStdoutEquals(const std::string& expected) {
        ASSERT_THAT(stdout_, StrEq(expected)) << "wrong stdout output";
    }

    // Access private bugreport_path_
    const std::string& GetBugreportPath() {
        return client_->bugreport_path_;
    }

  protected:
    sp<NiceMock<MockBinder>> binder_;
    sp<NiceMock<MockDumpstate>> ds_;
    sp<DumpstateClient> client_;
    std::string stdout_;
};

#define EXPECT_START_BUGREPORT_ONCE(obj, ret_status, reaction)  \
    EXPECT_CALL(obj, startBugreport()).Times(1).WillRepeatedly( \
            DoAll(Invoke(reaction), Return(ret_status)))

// Tests 'bugreportz', without any argument - it will ignore progress lines.
TEST_F(DumpstateClientTest, NoArgument) {
    EXPECT_START_BUGREPORT_ONCE(*ds_, Status::ok(), [&]() {
        client_->onProgress(0);
        client_->onProgress(42);
        client_->onFinished();
    });

    Bugreportz(false, client_);

    AssertStdoutEquals(base::StringPrintf(
        "OK:%s\n", GetBugreportPath().c_str()));
}

// Tests 'bugreportz -p' - it will just echo dumpstate's output to stdout
TEST_F(DumpstateClientTest, WithProgress) {
    constexpr int target_progress = 50;
    EXPECT_START_BUGREPORT_ONCE(*ds_, Status::ok(), [&]() {
        client_->onProgress(0);
        client_->onProgress(0);
        client_->onProgress(target_progress);
        client_->onFinished();
    });

    Bugreportz(true, client_);

    auto path = GetBugreportPath().c_str();
    AssertStdoutEquals(base::StringPrintf(
        "BEGIN:%s\n"
        "PROGRESS:0/100\n"
        "PROGRESS:%d/100\n"
        "OK:%s\n",
        path, target_progress, path));
}

TEST_F(DumpstateClientTest, StartBugreportHappy) {
    EXPECT_START_BUGREPORT_ONCE(*ds_, Status::ok(), [&]() {
        client_->onProgress(0);
        client_->onFinished();
    });

    ASSERT_EQ(::bugreportz(/*show_progress=*/true, client_), EXIT_SUCCESS);
}

TEST_F(DumpstateClientTest, AnotherReportInProgress) {
    const int err_code = IDumpstateListener::BUGREPORT_ERROR_ANOTHER_REPORT_IN_PROGRESS;
    const Status st = Status::fromExceptionCode(Status::EX_SERVICE_SPECIFIC);
    EXPECT_START_BUGREPORT_ONCE(*ds_, st, [&]() {
        client_->onError(err_code);
    });

    ASSERT_EQ(::bugreportz(/*show_progress=*/true, client_), EXIT_FAILURE);
}

TEST_F(DumpstateClientTest, StartBugreportInvalidInput) {
    const int err_code = IDumpstateListener::BUGREPORT_ERROR_INVALID_INPUT;
    const Status st = Status::fromExceptionCode(Status::EX_TRANSACTION_FAILED);
    EXPECT_START_BUGREPORT_ONCE(*ds_, st, [&]() {
        client_->onError(err_code);
    });

    ASSERT_EQ(::bugreportz(/*show_progress=*/true, client_), EXIT_FAILURE);
}

TEST_F(DumpstateClientTest, StartBugreportRuntimeError) {
    const int err_code = IDumpstateListener::BUGREPORT_ERROR_RUNTIME_ERROR;
    EXPECT_START_BUGREPORT_ONCE(*ds_, Status::ok(), [&]() {
        client_->binderDied(wp<MockBinder>(binder_));
    });

    ASSERT_EQ(::bugreportz(/*show_progress=*/true, client_), EXIT_FAILURE);
}

} // namespace android::os::bugreportz
