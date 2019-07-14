/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define BPF_FS_PATH "/sys/fs/bpf/"
#define BPF_FILENAME "suspend_stats"
#define EVENT_TYPE "power"
#define EVENT_NAME "suspend_resume"

#include "suspendstats.h"

#include <sys/stat.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <libbpf.h>
#include <log/log.h>
#include <string>
#include <cerrno>

static constexpr uint32_t BPF_OPEN_FLAGS = BPF_F_RDONLY;


using android::base::unique_fd;
using android::bpf::BpfMap;

namespace android {
namespace bpf {
namespace suspendstats {

// Write a string to a file, returning true if the write was successful.
static bool writeStr(const std::string& path, const std::string& str) {
    unique_fd fd(TEMP_FAILURE_RETRY(::open(path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (fd == -1) {
        LOG(WARNING) << "error opening, " << path << " errno: " << errno;
        return false;
    }
    ssize_t len = strlen(str.c_str());
    if (write(fd, str.c_str(), len) != len) {
        LOG(WARNING) << "error writing, " << str << " to " << path << " errno: " << errno;
        return false;
    }

    return true;
}

static bool enableTraceEvent(const std::string& eventType, const std::string& eventName) {
    std::string basePath = "/sys/kernel/debug/tracing/events/";
    std::string enablePath = basePath + eventType + "/" + eventName + "/enable";
    return writeStr(enablePath, "1");
}


/* Allow other processes to read the map */
static bool enableMapRead(const std::string& mapName) {
    std::string baseMapPath = BPF_FS_PATH "map_" BPF_FILENAME "_";
    std::string mapPath = baseMapPath + mapName;
    return chmod(mapPath.c_str(), S_IRUSR | S_IWUSR | S_IROTH/* | S_IWOTH*/) == 0;
}

// Start tracking and aggregating data to be reported by suspend_stats
// Returns true on success, false otherwise.
// This function should *not* be called while tracking is already active;
// doing so is unnecessary and can lead to accounting errors.
bool startTrackingSuspendStats() {
    if (!enableTraceEvent(EVENT_TYPE, EVENT_NAME)) {
        LOG(ERROR) << "Failed to enable suspend_resume trace event, errno: " << errno;
        return false;
    }
    LOG(INFO) << "Enable suspend_resume trace event, : Success";

    std::string path = BPF_FS_PATH "prog_" BPF_FILENAME "_tracepoint_" EVENT_TYPE "_" EVENT_NAME;
    int prog_fd = bpf_obj_get(path.c_str());
    if (prog_fd < 0) {
        LOG(ERROR) << "Failed to get prog_fd for suspend_stats bpf program at " << path << ", errno: " << errno;
        return false;
    }
    LOG(INFO) << "Get prog_fd for suspend_stats bpf program at " << path << ": Success";

    if (bpf_attach_tracepoint(prog_fd, EVENT_TYPE, EVENT_NAME) < 0) {
        LOG(ERROR) << "Failed to attach suspend_stats bpf program to tracepoint, errno: " << errno;
        return false;
    }
    LOG(INFO) << "Attach suspend_stats bpf program to tracepoint: Success";

    std::string mapName = "suspendstats_map";
    if (!enableMapRead(mapName)) {
        LOG(ERROR) << "Failed to enable suspendstats map read for, " << mapName << ", errno: " << errno;
        return false;
    }
    LOG(INFO) << "Enable suspendstats map read for, " << mapName << ": Success";

    return true;
}

// Just for testing
int getTimesTrigerred() {
    std::string baseMapPath = BPF_FS_PATH "map_" BPF_FILENAME "_";
    std::string mapName = "suspendstats_map";
    std::string mapPath = baseMapPath + mapName;
    unique_fd mapFd(mapRetrieve(mapPath.c_str(), BPF_OPEN_FLAGS /* TODO: 0 for read and write */));
    if (mapFd < 0) {
        LOG(WARNING) << "Cannot open: " <<  mapPath << " fd to get times tirgerred, errno: " << errno;
        return -1;
    }
    BpfMap<uint32_t, uint32_t> statsMap(mapFd.get());
    /*
    if (!isOk(statsMap.writeValue(0, 55555, BPF_ANY))) {
        LOG(WARNING) << "Failed to write magic number to suspend stats map, errno: " << errno;
        return -1;
    }
    */
    auto status = statsMap.readValue(0);
    if (!isOk(status)) {
        LOG(WARNING) << "Cannot read times triggered from suspendstats map, errno: " << errno;
        return -1;
    }
    LOG(WARNING) << "Read times trigerred from suspendstats map: " << status.value() << " : Success";
    return status.value();
}

} // namespace suspendstats
} // namespace bpf
} // namespace android
