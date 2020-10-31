// Copyright 2016 Google Inc. All Rights Reserved.
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

#ifndef BUGREPORTZ_H
#define BUGREPORTZ_H

#include <android-base/properties.h>
#include <android/os/BnDumpstateListener.h>
#include <android/os/IDumpstate.h>
#include <android/os/IDumpstateListener.h>

#include <future>

class DumpstateHelper {
  public:
    class DumpstateListener : public android::os::BnDumpstateListener,
                              public android::IBinder::DeathRecipient {
      public:
        DumpstateListener(DumpstateHelper& helper);
        android::binder::Status onProgress(int32_t progress) override;
        android::binder::Status onError(int32_t error_code) override;
        android::binder::Status onFinished() override;
        android::binder::Status onScreenshotTaken(bool success) override;
        android::binder::Status onUiIntensiveBugreportDumpsFinished(
            const android::String16& callingpackage) override;
        void binderDied(const android::wp<IBinder>& who) override;

      private:
        static constexpr std::string_view kBEGIN_PREFIX{"BEGIN:"};
        static constexpr std::string_view kPROGRESS_PREFIX{"PROGRESS:"};
        // A flag indicate that BEGIN message has sent.
        bool begin_ = false;
        std::mutex lock_;
        // For accessing data
        DumpstateHelper& helper_;

        void write(const std::string& line);
    };

    DumpstateHelper(int fd = dup(STDOUT_FILENO)) noexcept;

  private:
    friend int bugreportz(bool, DumpstateHelper);

    /* Prepare dumpstate binder service. Calling in ctor. */
    android::sp<android::os::IDumpstate> GetService();
    /* Initialize dumpstate listener. */
    android::sp<android::os::IDumpstateListener> CreateListener();

    android::sp<android::os::IDumpstate> ds_;
    android::sp<android::os::IDumpstateListener> listener_;

    // Wait until the value set in onFinish/onError of the listener before termination.
    std::promise<void> promise_finish_;
    // When not invoked with the -p option to show progress, it must skip BEGIN and PROGRESS lines
    // otherwise it will break adb (which is expecting either OK or FAIL).
    bool show_progress_ = true;
    //
    int fd_;

    //
    // Keep the implementations below in sync with dumpstates'
    //
    std::string date_{GetLocaltimeString()};
    std::string bugreport_path_{GetPath(".zip")};
    // Here not shows dumpstate's real pid, but literal "*" instead.
    std::string log_path_{GetPath("-dumpstate_log-*.txt")};

    // Returns the name of bugreport file name.
    std::string GetLocaltimeString() const;

    // Returns the basename of bugreport file name.
    std::string GetBasename() const;

    // Returns the full path of a file with the extension |suffix| based on the
    // `/bugreports` directory, device name, build ID and local time.
    //
    // Note that the implementation is similar to Dumpstate::GetPath except in some
    // bugreport modes, telephony and wifi, it would have an additional infix in the
    // file name.
    std::string GetPath(const std::string& suffix) const;

    // Create parent directories for a given |path|. Keep in sync with `create_parent_dirs()` in dumpstate.
    void CreateParentDirs(const char* /*path*/);
};

// Calls dumpstate via binder and output its result to stdout.
int bugreportz(bool show_progress, DumpstateHelper helper = DumpstateHelper());

// Calls dumpstate using the given socket and write the file content to stdout
// instead of file location. Ownership of the socket is not transferred.
int bugreportz_stream(int s);

#endif  // BUGREPORTZ_H
