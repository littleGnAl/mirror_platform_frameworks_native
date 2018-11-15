/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "rss_hwm_reset"

#include <dirent.h>

#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <log/log.h>

// Resets RSS HWM counter for the selected process by writing 5 to
// /proc/PID/clear_refs.
bool reset_rss_hwm(const char* pid) {
    std::string clear_refs_path =
            ::android::base::StringPrintf("/proc/%s/clear_refs", pid);
    return ::android::base::WriteStringToFile("5", clear_refs_path);
}

// Clears RSS HWM counters for all currently running processes.
int main(int /* argc */, char** /* argv[] */) {
    DIR* dirp = opendir("/proc");
    if (dirp == NULL) {
        ALOGE("unable to read /proc");
        return 1;
    }
    struct dirent* entry;
    int reset_processes = 0;
    while ((entry = readdir(dirp)) != NULL) {
        const char* pid = entry->d_name;
        while (*pid) {
            if (*pid < '0' || *pid > '9') break;
            pid++;
        }
        if (*pid != 0) continue;

        pid = entry->d_name;
        bool result = reset_rss_hwm(pid);
        if (result) {
            reset_processes++;
        } else {
            ALOGE("unable to reset RSS HWM for pid=%s", pid);
        }
    }
    ALOGD("cleared RSS HWM for %d processes", reset_processes);
    return 0;
}
