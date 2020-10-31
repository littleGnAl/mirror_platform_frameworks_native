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
#include "TestableDumpstateClient.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

using ::testing::_;
using ::testing::StrEq;
using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStdout;
using ::android::os::bugreportz::test::MockDumpstate;
using ::android::os::bugreportz::test::TestableDumpstateClient;

class BugreportzTest : public ::testing::Test {
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
    void Bugreportz(bool show_progress) {
        close(write_fd_);
        write_fd_ = -1;

        CaptureStdout();
        android::os::bugreportz::test::Factory factory;
        auto client = std::make_unique<android::os::bugreportz::DumpstateClient>(read_fd_, factory);
        int status = bugreportz(show_progress, std::move(client));

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

  private:
    int read_fd_;
    int write_fd_;
    std::string stdout_;
};

// TODO: fix and verify BugreportzTest with mock client

// Tests 'bugreportz', without any argument - it will ignore progress lines.
TEST_F(BugreportzTest, DISABLED_NoArgument) {
    WriteToSocket("BEGIN:THE IGNORED PATH WARS HAS!\n");  // Should be ommited.
    WriteToSocket("What happens on 'dumpstate',");
    WriteToSocket("stays on 'bugreportz'.\n");
    WriteToSocket("PROGRESS:Y U NO OMITTED?\n");  // Should be ommited.
    WriteToSocket("But ");
    WriteToSocket("PROGRESS IN THE MIDDLE");  // Ok - not starting a line.
    WriteToSocket(" is accepted\n");

    Bugreportz(false);

    AssertStdoutEquals(
        "What happens on 'dumpstate',stays on 'bugreportz'.\n"
        "But PROGRESS IN THE MIDDLE is accepted\n");
}

// Tests 'bugreportz -p' - it will just echo dumpstate's output to stdout
TEST_F(BugreportzTest, DISABLED_WithProgress) {
    WriteToSocket("BEGIN:I AM YOUR PATH\n");
    WriteToSocket("What happens on 'dumpstate',");
    WriteToSocket("stays on 'bugreportz'.\n");
    WriteToSocket("PROGRESS:IS INEVITABLE\n");
    WriteToSocket("PROG");
    WriteToSocket("RESS:IS NOT AUTOMATIC\n");
    WriteToSocket("Newline is optional");

    Bugreportz(true);

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

TEST(DumpstateClientTest, StartBugreport) {
    sp<MockDumpstate> ds = sp<MockDumpstate>::make();
    EXPECT_CALL(*ds, startBugreport(_,_,_,_,_,_,_)).Times(testing::AtLeast(1));
    auto client = TestableDumpstateClient(dup(STDOUT_FILENO), ds);

    Status st = client.StartBugreport(/*show_progress=*/true);
    EXPECT_TRUE(st.isOk());
}