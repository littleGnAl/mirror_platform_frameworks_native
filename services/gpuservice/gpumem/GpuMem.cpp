/*
 * Copyright 2020 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "GpuMem"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "gpumem/GpuMem.h"

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <libbpf.h>
#include <libbpf_android.h>
#include <log/log.h>
#include <unistd.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <unordered_map>
#include <vector>

namespace android {

using base::StringAppendF;
using base::unique_fd;

class GpuMemProcInfo {
public:
    uint32_t pid;
    uint64_t size;
    uint64_t imported_size;

    GpuMemProcInfo(uint32_t pid, uint64_t size, uint64_t imported_size)
          : pid(pid), size(size), imported_size(imported_size) {}
};

static bool FtraceEventHasField(const char* subsystem, const char* event, const char* field) {
    using base::ReadFileToString;
    using base::Split;
    using base::StartsWith;
    using base::StringPrintf;
    using base::Trim;

    std::string path = StringPrintf("/sys/kernel/tracing/events/%s/%s/format", subsystem, event);
    std::string debugfs_path =
            StringPrintf("/sys/kernel/tracing/events/%s/%s/format", subsystem, event);

    std::string format;
    if (!ReadFileToString(path, &format) && !ReadFileToString(debugfs_path, &format)) {
        ALOGE("Failed to read ftrace event format for %s/%s", subsystem, event);
        return false;
    }

    auto lines = Split(format, "\n");
    for (auto& line : lines) {
        line = Trim(line);

        if (!StartsWith(line, "field:")) {
            continue;
        }

        auto field_name = Split(Trim(Split(line, ";")[0]), " ").back();
        if (field_name == field) {
            return true;
        }
    }

    return false;
}

GpuMem::~GpuMem() {
    bpf_detach_tracepoint(kGpuMemTraceGroup, kGpuMemTotalTracepoint);
}

void GpuMem::initialize(bool attach_tracepoint) {
    // Make sure bpf programs are loaded
    bpf::waitForProgsLoaded();

    mImportedMemSupported = FtraceEventHasField(kGpuMemTraceGroup, kGpuMemTotalTracepoint,
                                                kGpuMemImportedSizeField);

    ALOGI("GPU imported memory tracking is %ssupported", mImportedMemSupported ? "" : "not ");

    errno = 0;

    const char* bpf_prog_path = (mImportedMemSupported) ? kGpuMemProgPath : kGpuMemTotalProgPath;
    unique_fd fd{bpf::retrieveProgram(bpf_prog_path)};
    if (fd < 0) {
        ALOGE("Failed to retrieve pinned program from %s [%d(%s)]", bpf_prog_path, errno,
              strerror(errno));
        return;
    }

    // Attach the program to the tracepoint, and the tracepoint is automatically enabled here.
    if (attach_tracepoint) {
        errno = 0;
        int count = 0;
        while (bpf_attach_tracepoint(fd, kGpuMemTraceGroup, kGpuMemTotalTracepoint) < 0) {
            if (++count > kGpuWaitTimeout) {
                ALOGE("Failed to attach bpf program to %s/%s tracepoint [%d(%s)]",
                      kGpuMemTraceGroup, kGpuMemTotalTracepoint, errno, strerror(errno));
                return;
            }
            // Retry until GPU driver loaded or timeout.
            sleep(1);
        }
    }

    ALOGI("Attached bpf prog %s to tracepoint %s/%s", bpf_prog_path, kGpuMemTraceGroup,
          kGpuMemTotalTracepoint);

    // Use the read-only wrapper BpfMapRO to properly retrieve the read-only map.
    errno = 0;
    auto map = bpf::BpfMapRO<uint64_t, uint64_t>(kGpuMemTotalMapPath);
    if (!map.isValid()) {
        ALOGE("Failed to create bpf map from %s [%d(%s)]", kGpuMemTotalMapPath, errno,
              strerror(errno));
        return;
    }
    setGpuMemTotalMap(map);

    if (mImportedMemSupported) {
        errno = 0;
        auto mem_imported_map = bpf::BpfMapRO<uint64_t, uint64_t>(kGpuMemImportedMapPath);
        if (!mem_imported_map.isValid()) {
            ALOGE("Failed to create bpf map from %s [%d(%s)]", kGpuMemImportedMapPath, errno,
                  strerror(errno));
            return;
        }
        setGpuMemImportedMap(mem_imported_map);
    }

    mInitialized.store(true);
}

void GpuMem::setGpuMemTotalMap(bpf::BpfMap<uint64_t, uint64_t>& map) {
    mGpuMemTotalMap = std::move(map);
}

void GpuMem::setGpuMemImportedMap(bpf::BpfMap<uint64_t, uint64_t>& map) {
    mGpuMemImportedMap = std::move(map);
}

// Dump the snapshots of global and per process memory usage on all gpus
void GpuMem::dump(const Vector<String16>& /* args */, std::string* result) {
    ATRACE_CALL();

    if (!mInitialized.load() || !mGpuMemTotalMap.isValid()) {
        result->append("Failed to initialize GPU memory eBPF\n");
        return;
    }

    if (mImportedMemSupported && !mGpuMemImportedMap.isValid()) {
        result->append("Failed to initialize GPU imported mem eBPF map\n");
        return;
    }

    auto res = mGpuMemTotalMap.getFirstKey();
    if (!res.ok()) {
        result->append("GPU memory usage maps are empty\n");
        return;
    }

    // unordered_map<gpu_id, GpuMemProcInfo>
    std::unordered_map<uint32_t, std::vector<GpuMemProcInfo>> dumpMap;

    uint64_t key = res.value();
    while (true) {
        uint32_t gpu_id = key >> 32;
        uint32_t pid = key;

        res = mGpuMemTotalMap.readValue(key);
        if (!res.ok()) break;
        uint64_t size = res.value();

        uint64_t imported_size = 0;
        if (mImportedMemSupported) {
            if (res = mGpuMemImportedMap.readValue(key); res.ok()) {
                imported_size = res.value();
            }
        }

        dumpMap[gpu_id].emplace_back(pid, size, imported_size);

        res = mGpuMemTotalMap.getNextKey(key);
        if (!res.ok()) break;
        key = res.value();
    }

    for (auto& gpu : dumpMap) {
        if (gpu.second.empty()) continue;
        StringAppendF(result, "Memory snapshot for GPU %u:\n", gpu.first);

        std::sort(gpu.second.begin(), gpu.second.end(),
                  [](auto& l, auto& r) { return l.pid < r.pid; });

        int i = 0;
        if (gpu.second[0].pid != 0) {
            StringAppendF(result, "Global total: N/A");
            if (mImportedMemSupported) {
                StringAppendF(result, ", imported: N/A");
            }
            StringAppendF(result, "\n");
        } else {
            StringAppendF(result, "Global total: %" PRIu64, gpu.second[0].size);
            if (mImportedMemSupported) {
                StringAppendF(result, ", imported: %" PRIu64, gpu.second[0].imported_size);
            }
            StringAppendF(result, "\n");
            i++;
        }
        for (; i < gpu.second.size(); i++) {
            StringAppendF(result, "Proc %u total: %" PRIu64, gpu.second[i].pid, gpu.second[i].size);
            if (mImportedMemSupported) {
                StringAppendF(result, ", imported: %" PRIu64, gpu.second[i].imported_size);
            }
            StringAppendF(result, "\n");
        }
    }
}

void GpuMem::traverseGpuMemInfo(
        const std::function<void(int64_t ts, uint32_t gpuId, uint32_t pid, uint64_t size,
                                 uint64_t imported_size)>& callback) {
    auto res = mGpuMemTotalMap.getFirstKey();
    if (!res.ok()) return;
    uint64_t key = res.value();
    while (true) {
        uint32_t gpu_id = key >> 32;
        uint32_t pid = key;

        res = mGpuMemTotalMap.readValue(key);
        if (!res.ok()) break;
        uint64_t size = res.value();

        uint64_t imported_size = 0;
        if (mImportedMemSupported) {
            if (res = mGpuMemImportedMap.readValue(key); res.ok()) {
                imported_size = res.value();
            }
        }

        callback(systemTime(), gpu_id, pid, size, imported_size);
        res = mGpuMemTotalMap.getNextKey(key);
        if (!res.ok()) break;
        key = res.value();
    }
}

} // namespace android
