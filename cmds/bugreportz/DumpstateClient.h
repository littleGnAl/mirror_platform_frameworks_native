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

#ifndef DUMPSTATE_CLIENT_H
#define DUMPSTATE_CLIENT_H

#include <android-base/properties.h>
#include <android/os/BnDumpstateListener.h>
#include <android/os/IDumpstate.h>
#include <android/os/IDumpstateListener.h>

#include <future>
#include <memory>

using android::sp;
using android::binder::Status;
using android::os::IDumpstate;
using android::os::IDumpstateListener;
using std::unique_ptr;

class DumpstateClient;

// Interface for binder injection
class IDumpstateFactory {
  public:
    virtual sp<IDumpstate> CreateService(sp<android::IBinder::DeathRecipient> recipient) = 0;
    virtual ~IDumpstateFactory(){};
};

class DumpstateClient : public android::os::BnDumpstateListener,
                        public android::IBinder::DeathRecipient {
  public:
    // Client members
    explicit DumpstateClient(int fd, unique_ptr<IDumpstateFactory> factory) noexcept;

    Status StartBugreport(bool show_progress);

    void Wait();

    // BnDumpstateListener & DeathRecipient members
    Status onProgress(int32_t progress) override;
    Status onError(int32_t error_code) override;
    Status onFinished() override;
    Status onScreenshotTaken(bool success) override;
    Status onUiIntensiveBugreportDumpsFinished(const android::String16& callingpackage) override;
    void binderDied(const android::wp<IBinder>& who) override;

    class DumpstateFactory : public IDumpstateFactory {
        sp<IDumpstate> CreateService(sp<android::IBinder::DeathRecipient> recipient) override;
    };

    sp<IDumpstate> ds_;

  private:
    // Wait until the value set in onFinish/onError of the listener before termination.
    std::promise<void> promise_finish_;
    // When not invoked with the -p option to show progress, it must skip BEGIN and PROGRESS lines
    // otherwise it will break adb (which is expecting either OK or FAIL).
    bool show_progress_ = true;
    //
    int fd_;

    // static constexpr char
    static constexpr char kBEGIN_PREFIX[] = "BEGIN:";
    static constexpr char kPROGRESS_PREFIX[] = "PROGRESS:";
    std::mutex lock_;

    // A flag indicate that BEGIN message has sent.
    bool begin_ = false;

    void write(const std::string& line);

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

    // Create parent directories for a given |path|.
    // Keep in sync with `create_parent_dirs()` in dumpstate.
    void CreateParentDirs(const char* /*path*/);
};

#endif  // DUMPSTATE_CLIENT_H
