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

#include <gmock/gmock.h>
#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include <string>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Test;
using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStdout;
using ::android::base::unique_fd;
using ::android::binder::Status;
using ::android::os::IDumpstateListener;
using ::android::os::bugreportz::DumpstateClient;

using namespace ::android;

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
    MOCK_METHOD(Status, startBugreport,
                ((int32_t callingUid), (const std::string& callingPackage),
                (unique_fd bugreportFd), (unique_fd screenshotFd),
                (int32_t bugreportMode),
                (const sp<android::os::IDumpstateListener>& listener),
                (bool isScreenshotRequested)),
                (override));
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
    void Bugreportz(bool show_progress, sp<DumpstateClient> client) {
        close(write_fd_);
        write_fd_ = -1;

        CaptureStdout();
        int status = bugreportz(show_progress, client);

        close(read_fd_);
        read_fd_ = -1;
        stdout_ = GetCapturedStdout();

        ASSERT_EQ(0, status) << "bugrepotz() call failed (stdout: " << stdout_ << ")";
    }

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

    sp<DumpstateClient> CreateClient() {
        binder_ = sp<MockBinder>::make();
        ds_ = sp<MockDumpstate>::make();
        client_ = sp<DumpstateClient>::make(write_fd_, ds_);
        ON_CALL(*ds_, onAsBinder).WillByDefault(Return(binder_.get()));
        return client_;
    }

  protected:
    sp<MockBinder> binder_ = nullptr;
    sp<MockDumpstate> ds_ = nullptr;
    sp<DumpstateClient> client_ = nullptr;

  private:
    int read_fd_;
    int write_fd_;
    std::string stdout_;
};

// TODO: fix and verify BugreportzTest with mock client

// Tests 'bugreportz', without any argument - it will ignore progress lines.
TEST_F(BugreportzTest, NoArgument) {
    client_ = CreateClient();
    client_->onProgress(0);
    client_->onProgress(42);
    client_->onFinished();

    Bugreportz(false, client_);

    AssertStdoutEquals(
        "What happens on 'dumpstate',stays on 'bugreportz'.\n"
        "But PROGRESS IN THE MIDDLE is accepted\n");
}

// Tests 'bugreportz -p' - it will just echo dumpstate's output to stdout
TEST_F(BugreportzTest, WithProgress) {
    client_ = CreateClient();
    client_->onProgress(0);
    client_->onProgress(0);
    client_->onProgress(50);
    client_->onFinished();

    Bugreportz(true, client_);

    AssertStdoutEquals(
        "BEGIN:I AM YOUR PATH\n"
        "What happens on 'dumpstate',stays on 'bugreportz'.\n"
        "PROGRESS:IS INEVITABLE\n"
        "PROGRESS:IS NOT AUTOMATIC\n"
        "Newline is optional");
}

// Tests 'bugreportz -s' - just echo data
TEST_F(BugreportzTest, WithStream) {
    char emptyZip[] = {0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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
        client_ = sp<DumpstateClient>::make(dup(STDOUT_FILENO), ds_);

        ON_CALL(*ds_, onAsBinder).WillByDefault(Return(binder_.get()));
    }
  protected:
    sp<MockBinder> binder_ = nullptr;
    sp<MockDumpstate> ds_ = nullptr;
    sp<DumpstateClient> client_ = nullptr;
};

TEST_F(DumpstateClientTest, StartBugreportHappy) {
    EXPECT_CALL(*ds_, startBugreport(_,_,_,_,_,_,_)).WillRepeatedly(
            DoAll(Invoke([&](){client_->onFinished();}),
                  Return(Status::ok())));

    ASSERT_EQ(bugreportz(/*show_progress=*/true, client_), EXIT_SUCCESS);
}

TEST_F(DumpstateClientTest, AnotherReportInProgress) {
    const int err_code = IDumpstateListener::BUGREPORT_ERROR_ANOTHER_REPORT_IN_PROGRESS;
    EXPECT_CALL(*ds_, startBugreport(_,_,_,_,_,_,_)).WillRepeatedly(
            DoAll(Invoke([&](){client_->onError(err_code);}),
                  Return(Status::fromExceptionCode(Status::EX_SERVICE_SPECIFIC))));

    ASSERT_EQ(bugreportz(/*show_progress=*/true, client_), EXIT_FAILURE);
}
