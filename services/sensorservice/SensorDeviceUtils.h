/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef ANDROID_SENSOR_DEVICE_UTIL
#define ANDROID_SENSOR_DEVICE_UTIL

#include <android/hidl/manager/1.0/IServiceNotification.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <string>
#include <thread>

using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hidl::manager::V1_0::IServiceNotification;

namespace android {
namespace SensorDeviceUtils {

template <typename S>
class ServiceRestartWaiter : public IServiceNotification {
public:

    ServiceRestartWaiter(const std::string &name = std::string("default")) :
            mRegistered(false), mName(name) {
        mRegistered = S::registerForNotifications(mName, this);
        ALOGE_IF(!mRegistered, "Cannot register service notification, use default wait time");
    }

    Return<void> onRegistration(const hidl_string &fqName,
                                const hidl_string &name,
                                bool preexisting) override {
        ALOGD("onRegistration fqName %s, name %s, preexisting %d",
              fqName.c_str(), name.c_str(), preexisting);

        if (preexisting == 0) {
            std::lock_guard<std::mutex> lk(mLock);
            mRestartObserved = true;
            mCondition.notify_all();
        }

        return Void();
    }

    void reset() {
        std::lock_guard<std::mutex> lk(mLock);
        mRestartObserved = false;
    }

    bool wait() {
        constexpr int DEFAULT_WAIT_MS = 100;
        constexpr int TIMEOUT_MS = 1000;

        ALOGE_IF(!mRegistered, "Cannot register service notification, use default wait time");
        if (mRegistered) {
            std::unique_lock<std::mutex> lk(mLock);
            return mCondition.wait_for(lk, std::chrono::milliseconds(TIMEOUT_MS),
                                       [this]{return mRestartObserved;});
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_WAIT_MS));
            // not sure if service is actually restarted
            return false;
        }
    }
private:
    bool mRegistered;
    std::string mName;

    std::mutex mLock;
    std::condition_variable mCondition;
    bool mRestartObserved;
};

class HidlTransportErrorLog {
 public:

    HidlTransportErrorLog() {
        mTs = 0;
        mCount = 0;
    }

    HidlTransportErrorLog(time_t ts, int count) {
        mTs = ts;
        mCount = count;
    }

    String8 toString() const {
        String8 result;
        struct tm *timeInfo = localtime(&mTs);
        result.appendFormat("%02d:%02d:%02d :: %d", timeInfo->tm_hour, timeInfo->tm_min,
                            timeInfo->tm_sec, mCount);
        return result;
    }

private:
    time_t mTs; // timestamp of the error
    int mCount;   // number of transport errors observed
};
} // namespace SensorDeviceUtils
} // namespace android;

#endif // ANDROID_SENSOR_SERVICE_UTIL
