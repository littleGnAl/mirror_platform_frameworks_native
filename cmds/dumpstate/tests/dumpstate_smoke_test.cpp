/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fcntl.h>
#include <libgen.h>

#include <android-base/file.h>
#include <android/os/BnDumpstate.h>
#include <android/os/BnDumpstateListener.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <cutils/properties.h>
#include <ziparchive/zip_archive.h>

#include "dumpstate.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

namespace android {
namespace os {
namespace dumpstate {

using ::testing::Test;
using ::std::literals::chrono_literals::operator""s;
using android::base::unique_fd;

class DumpstateListener;

namespace {

sp<IDumpstate> GetDumpstateService() {
    return android::interface_cast<IDumpstate>(
        android::defaultServiceManager()->getService(String16("dumpstate")));
}

int OpenForWrite(const std::string& filename) {
    return TEMP_FAILURE_RETRY(open(filename.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
}

}  // namespace

struct SectionInfo {
    std::string name;
    status_t status;
    int32_t size_bytes;
    int32_t duration_ms;
};

/**
 * Listens to bugreport progress and updates the user by writing the progress to STDOUT. All the
 * section details generated by dumpstate are added to a vector to be used by Tests later.
 */
class DumpstateListener : public BnDumpstateListener {
  public:
    DumpstateListener(int fd, std::shared_ptr<std::vector<SectionInfo>> sections)
        : out_fd_(fd), sections_(sections) {
    }

    DumpstateListener(int fd) : out_fd_(fd) {
    }

    binder::Status onProgress(int32_t progress) override {
        dprintf(out_fd_, "\rIn progress %d", progress);
        return binder::Status::ok();
    }

    binder::Status onError(int32_t error_code) override {
        std::lock_guard<std::mutex> lock(lock_);
        error_code_ = error_code;
        dprintf(out_fd_, "\rError code %d", error_code);
        return binder::Status::ok();
    }

    binder::Status onFinished() override {
        std::lock_guard<std::mutex> lock(lock_);
        is_finished_ = true;
        dprintf(out_fd_, "\rFinished");
        return binder::Status::ok();
    }

    binder::Status onProgressUpdated(int32_t progress) override {
        dprintf(out_fd_, "\rIn progress %d/%d", progress, max_progress_);
        return binder::Status::ok();
    }

    binder::Status onMaxProgressUpdated(int32_t max_progress) override {
        std::lock_guard<std::mutex> lock(lock_);
        max_progress_ = max_progress;
        return binder::Status::ok();
    }

    binder::Status onSectionComplete(const ::std::string& name, int32_t status, int32_t size_bytes,
                                     int32_t duration_ms) override {
        std::lock_guard<std::mutex> lock(lock_);
        if (sections_.get() != nullptr) {
            sections_->push_back({name, status, size_bytes, duration_ms});
        }
        return binder::Status::ok();
    }

    bool getIsFinished() {
        std::lock_guard<std::mutex> lock(lock_);
        return is_finished_;
    }

    int getErrorCode() {
        std::lock_guard<std::mutex> lock(lock_);
        return error_code_;
    }

  private:
    int out_fd_;
    int max_progress_ = 5000;
    int error_code_ = -1;
    bool is_finished_ = false;
    std::shared_ptr<std::vector<SectionInfo>> sections_;
    std::mutex lock_;
};

/**
 * Generates bug report and provide access to the bug report file and other info for other tests.
 * Since bug report generation is slow, the bugreport is only generated once.
 */
class ZippedBugreportGenerationTest : public Test {
  public:
    static std::shared_ptr<std::vector<SectionInfo>> sections;
    static Dumpstate& ds;
    static std::chrono::milliseconds duration;
    static void SetUpTestCase() {
        property_set("dumpstate.options", "bugreportplus");
        // clang-format off
        char* argv[] = {
            (char*)"dumpstate",
            (char*)"-d",
            (char*)"-z",
            (char*)"-B",
            (char*)"-o",
            (char*)dirname(android::base::GetExecutablePath().c_str())
        };
        // clang-format on
        sp<DumpstateListener> listener(new DumpstateListener(dup(fileno(stdout)), sections));
        ds.listener_ = listener;
        ds.listener_name_ = "Smokey";
        ds.report_section_ = true;
        auto start = std::chrono::steady_clock::now();
        ds.ParseCommandlineAndRun(ARRAY_SIZE(argv), argv);
        auto end = std::chrono::steady_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    }

    static const char* getZipFilePath() {
        return ds.GetPath(".zip").c_str();
    }
};
std::shared_ptr<std::vector<SectionInfo>> ZippedBugreportGenerationTest::sections =
    std::make_shared<std::vector<SectionInfo>>();
Dumpstate& ZippedBugreportGenerationTest::ds = Dumpstate::GetInstance();
std::chrono::milliseconds ZippedBugreportGenerationTest::duration = 0s;

TEST_F(ZippedBugreportGenerationTest, IsGeneratedWithoutErrors) {
    EXPECT_EQ(access(getZipFilePath(), F_OK), 0);
}

TEST_F(ZippedBugreportGenerationTest, Is3MBto30MBinSize) {
    struct stat st;
    EXPECT_EQ(stat(getZipFilePath(), &st), 0);
    EXPECT_GE(st.st_size, 3000000 /* 3MB */);
    EXPECT_LE(st.st_size, 30000000 /* 30MB */);
}

TEST_F(ZippedBugreportGenerationTest, TakesBetween30And150Seconds) {
    EXPECT_GE(duration, 30s) << "Expected completion in more than 30s. Actual time "
                             << duration.count() << " s.";
    EXPECT_LE(duration, 150s) << "Expected completion in less than 150s. Actual time "
                              << duration.count() << " s.";
}

/**
 * Run tests on contents of zipped bug report.
 */
class ZippedBugReportContentsTest : public Test {
  public:
    ZipArchiveHandle handle;
    void SetUp() {
        ASSERT_EQ(OpenArchive(ZippedBugreportGenerationTest::getZipFilePath(), &handle), 0);
    }
    void TearDown() {
        CloseArchive(handle);
    }

    void FileExists(const char* filename, uint32_t minsize, uint32_t maxsize) {
        ZipEntry entry;
        EXPECT_EQ(FindEntry(handle, filename, &entry), 0);
        EXPECT_GT(entry.uncompressed_length, minsize);
        EXPECT_LT(entry.uncompressed_length, maxsize);
    }
};

TEST_F(ZippedBugReportContentsTest, ContainsMainEntry) {
    ZipEntry mainEntryLoc;
    // contains main entry name file
    EXPECT_EQ(FindEntry(handle, "main_entry.txt", &mainEntryLoc), 0);

    char* buf = new char[mainEntryLoc.uncompressed_length];
    ExtractToMemory(handle, &mainEntryLoc, (uint8_t*)buf, mainEntryLoc.uncompressed_length);
    delete[] buf;

    // contains main entry file
    FileExists(buf, 1000000U, 50000000U);
}

TEST_F(ZippedBugReportContentsTest, ContainsVersion) {
    ZipEntry entry;
    // contains main entry name file
    EXPECT_EQ(FindEntry(handle, "version.txt", &entry), 0);

    char* buf = new char[entry.uncompressed_length + 1];
    ExtractToMemory(handle, &entry, (uint8_t*)buf, entry.uncompressed_length);
    buf[entry.uncompressed_length] = 0;
    EXPECT_STREQ(buf, ZippedBugreportGenerationTest::ds.version_.c_str());
    delete[] buf;
}

TEST_F(ZippedBugReportContentsTest, ContainsBoardSpecificFiles) {
    FileExists("dumpstate_board.bin", 1000000U, 80000000U);
    FileExists("dumpstate_board.txt", 100000U, 1000000U);
}

// Spot check on some files pulled from the file system
TEST_F(ZippedBugReportContentsTest, ContainsSomeFileSystemFiles) {
    // FS/proc/*/mountinfo size > 0
    FileExists("FS/proc/1/mountinfo", 0U, 100000U);

    // FS/data/misc/profiles/cur/0/*/primary.prof size > 0
    FileExists("FS/data/misc/profiles/cur/0/com.android.phone/primary.prof", 0U, 100000U);
}

/**
 * Runs tests on section data generated by dumpstate and captured by DumpstateListener.
 */
class BugreportSectionTest : public Test {
  public:
    int numMatches(const std::string& substring) {
        int matches = 0;
        for (auto const& section : *ZippedBugreportGenerationTest::sections) {
            if (section.name.find(substring) != std::string::npos) {
                matches++;
            }
        }
        return matches;
    }
    void SectionExists(const std::string& sectionName, int minsize) {
        for (auto const& section : *ZippedBugreportGenerationTest::sections) {
            if (sectionName == section.name) {
                EXPECT_GE(section.size_bytes, minsize);
                return;
            }
        }
        FAIL() << sectionName << " not found.";
    }
};

// Test all sections are generated without timeouts or errors
TEST_F(BugreportSectionTest, GeneratedWithoutErrors) {
    for (auto const& section : *ZippedBugreportGenerationTest::sections) {
        EXPECT_EQ(section.status, 0) << section.name << " failed with status " << section.status;
    }
}

TEST_F(BugreportSectionTest, Atleast3CriticalDumpsysSectionsGenerated) {
    int numSections = numMatches("DUMPSYS CRITICAL");
    EXPECT_GE(numSections, 3);
}

TEST_F(BugreportSectionTest, Atleast2HighDumpsysSectionsGenerated) {
    int numSections = numMatches("DUMPSYS HIGH");
    EXPECT_GE(numSections, 2);
}

TEST_F(BugreportSectionTest, Atleast50NormalDumpsysSectionsGenerated) {
    int allSections = numMatches("DUMPSYS");
    int criticalSections = numMatches("DUMPSYS CRITICAL");
    int highSections = numMatches("DUMPSYS HIGH");
    int normalSections = allSections - criticalSections - highSections;

    EXPECT_GE(normalSections, 50) << "Total sections less than 50 (Critical:" << criticalSections
                                  << "High:" << highSections << "Normal:" << normalSections << ")";
}

TEST_F(BugreportSectionTest, Atleast1ProtoDumpsysSectionGenerated) {
    int numSections = numMatches("proto/");
    EXPECT_GE(numSections, 1);
}

// Test if some critical sections are being generated.
TEST_F(BugreportSectionTest, CriticalSurfaceFlingerSectionGenerated) {
    SectionExists("DUMPSYS CRITICAL - SurfaceFlinger", /* bytes= */ 10000);
}

TEST_F(BugreportSectionTest, ActivitySectionsGenerated) {
    SectionExists("DUMPSYS CRITICAL - activity", /* bytes= */ 5000);
    SectionExists("DUMPSYS - activity", /* bytes= */ 10000);
}

TEST_F(BugreportSectionTest, CpuinfoSectionGenerated) {
    SectionExists("DUMPSYS CRITICAL - cpuinfo", /* bytes= */ 1000);
}

TEST_F(BugreportSectionTest, WindowSectionGenerated) {
    SectionExists("DUMPSYS CRITICAL - window", /* bytes= */ 20000);
}

TEST_F(BugreportSectionTest, ConnectivitySectionsGenerated) {
    SectionExists("DUMPSYS HIGH - connectivity", /* bytes= */ 5000);
    SectionExists("DUMPSYS - connectivity", /* bytes= */ 5000);
}

TEST_F(BugreportSectionTest, MeminfoSectionGenerated) {
    SectionExists("DUMPSYS HIGH - meminfo", /* bytes= */ 100000);
}

TEST_F(BugreportSectionTest, BatteryStatsSectionGenerated) {
    SectionExists("DUMPSYS - batterystats", /* bytes= */ 1000);
}

TEST_F(BugreportSectionTest, WifiSectionGenerated) {
    SectionExists("DUMPSYS - wifi", /* bytes= */ 100000);
}

class DumpstateBinderTest : public Test {
  protected:
    void SetUp() override {
        // In case there is a stray service, stop it first.
        property_set("ctl.stop", "bugreportd");
        // dry_run results in a faster bugreport.
        property_set("dumpstate.dry_run", "true");
        // We need to receive some async calls later. Ensure we have binder threads.
        ProcessState::self()->startThreadPool();
    }

    void TearDown() override {
        property_set("ctl.stop", "bugreportd");
        property_set("dumpstate.dry_run", "");

        unlink("/data/local/tmp/tmp.zip");
        unlink("/data/local/tmp/tmp.png");
    }

    // Waits until listener gets the callbacks.
    void WaitTillExecutionComplete(DumpstateListener* listener) {
        // Wait till one of finished, error or timeout.
        static const int kBugreportTimeoutSeconds = 120;
        int i = 0;
        while (!listener->getIsFinished() && listener->getErrorCode() == -1 &&
               i < kBugreportTimeoutSeconds) {
            sleep(1);
            i++;
        }
    }
};

TEST_F(DumpstateBinderTest, Baseline) {
    // In the beginning dumpstate binder service is not running.
    sp<android::os::IDumpstate> ds_binder(GetDumpstateService());
    EXPECT_EQ(ds_binder, nullptr);

    // Start bugreportd, which runs dumpstate binary with -w; which starts dumpstate service
    // and makes it wait.
    property_set("dumpstate.dry_run", "true");
    property_set("ctl.start", "bugreportd");

    // Now we are able to retrieve dumpstate binder service.
    ds_binder = GetDumpstateService();
    EXPECT_NE(ds_binder, nullptr);

    // Prepare arguments
    unique_fd bugreport_fd(OpenForWrite("/bugreports/tmp.zip"));
    unique_fd screenshot_fd(OpenForWrite("/bugreports/tmp.png"));

    EXPECT_NE(bugreport_fd.get(), -1);
    EXPECT_NE(screenshot_fd.get(), -1);

    sp<DumpstateListener> listener(new DumpstateListener(dup(fileno(stdout))));
    android::binder::Status status =
        ds_binder->startBugreport(123, "com.dummy.package", bugreport_fd, screenshot_fd,
                                  Dumpstate::BugreportMode::BUGREPORT_INTERACTIVE, listener);
    // startBugreport is an async call. Verify binder call succeeded first, then wait till listener
    // gets expected callbacks.
    EXPECT_TRUE(status.isOk());
    WaitTillExecutionComplete(listener.get());

    // Bugreport generation requires user consent, which we cannot get in a test set up,
    // so instead of getting is_finished_, we are more likely to get a consent error.
    EXPECT_TRUE(
        listener->getErrorCode() == IDumpstateListener::BUGREPORT_ERROR_USER_DENIED_CONSENT ||
        listener->getErrorCode() == IDumpstateListener::BUGREPORT_ERROR_USER_CONSENT_TIMED_OUT);

    // The service should have died on its own, freeing itself up for a new invocation.
    sleep(2);
    ds_binder = GetDumpstateService();
    EXPECT_EQ(ds_binder, nullptr);
}

TEST_F(DumpstateBinderTest, ServiceDies_OnInvalidInput) {
    // Start bugreportd, which runs dumpstate binary with -w; which starts dumpstate service
    // and makes it wait.
    property_set("ctl.start", "bugreportd");
    sp<android::os::IDumpstate> ds_binder(GetDumpstateService());
    EXPECT_NE(ds_binder, nullptr);

    // Prepare arguments
    unique_fd bugreport_fd(OpenForWrite("/data/local/tmp/tmp.zip"));
    unique_fd screenshot_fd(OpenForWrite("/data/local/tmp/tmp.png"));

    EXPECT_NE(bugreport_fd.get(), -1);
    EXPECT_NE(screenshot_fd.get(), -1);

    // Call startBugreport with bad arguments.
    sp<DumpstateListener> listener(new DumpstateListener(dup(fileno(stdout))));
    android::binder::Status status =
        ds_binder->startBugreport(123, "com.dummy.package", bugreport_fd, screenshot_fd,
                                  2000,  // invalid bugreport mode
                                  listener);
    EXPECT_EQ(listener->getErrorCode(), IDumpstateListener::BUGREPORT_ERROR_INVALID_INPUT);

    // The service should have died, freeing itself up for a new invocation.
    sleep(2);
    ds_binder = GetDumpstateService();
    EXPECT_EQ(ds_binder, nullptr);
}

TEST_F(DumpstateBinderTest, SimultaneousBugreportsNotAllowed) {
    // Start bugreportd, which runs dumpstate binary with -w; which starts dumpstate service
    // and makes it wait.
    property_set("dumpstate.dry_run", "true");
    property_set("ctl.start", "bugreportd");
    sp<android::os::IDumpstate> ds_binder(GetDumpstateService());
    EXPECT_NE(ds_binder, nullptr);

    // Prepare arguments
    unique_fd bugreport_fd(OpenForWrite("/data/local/tmp/tmp.zip"));
    unique_fd screenshot_fd(OpenForWrite("/data/local/tmp/tmp.png"));

    EXPECT_NE(bugreport_fd.get(), -1);
    EXPECT_NE(screenshot_fd.get(), -1);

    sp<DumpstateListener> listener1(new DumpstateListener(dup(fileno(stdout))));
    android::binder::Status status =
        ds_binder->startBugreport(123, "com.dummy.package", bugreport_fd, screenshot_fd,
                                  Dumpstate::BugreportMode::BUGREPORT_INTERACTIVE, listener1);
    EXPECT_TRUE(status.isOk());

    // try to make another call to startBugreport. This should fail.
    sp<DumpstateListener> listener2(new DumpstateListener(dup(fileno(stdout))));
    status = ds_binder->startBugreport(123, "com.dummy.package", bugreport_fd, screenshot_fd,
                                       Dumpstate::BugreportMode::BUGREPORT_INTERACTIVE, listener2);
    EXPECT_FALSE(status.isOk());
    WaitTillExecutionComplete(listener2.get());
    EXPECT_EQ(listener2->getErrorCode(),
              IDumpstateListener::BUGREPORT_ERROR_ANOTHER_REPORT_IN_PROGRESS);

    // Meanwhile the first call works as expected. Service should not die in this case.
    WaitTillExecutionComplete(listener1.get());

    // Bugreport generation requires user consent, which we cannot get in a test set up,
    // so instead of getting is_finished_, we are more likely to get a consent error.
    EXPECT_TRUE(
        listener1->getErrorCode() == IDumpstateListener::BUGREPORT_ERROR_USER_DENIED_CONSENT ||
        listener1->getErrorCode() == IDumpstateListener::BUGREPORT_ERROR_USER_CONSENT_TIMED_OUT);
}

}  // namespace dumpstate
}  // namespace os
}  // namespace android
