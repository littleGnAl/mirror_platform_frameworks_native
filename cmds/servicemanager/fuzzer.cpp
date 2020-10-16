/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "setup.h"

#include <fuzzbinder/fuzzbinder.h>
#include "setup.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // avoid timeouts
    if (size > 50000) return 0;

    android::sp<android::ServiceManager> manager = android::setupServiceManager("/dev/binder");
    android::fuzzBinder(manager, data, size);

    return 0;
}

#ifndef DEVICE_TARGET

// These functions aren't implemented for selinux on host, so implement them in
// a convenient way

struct selabel_handle;
extern "C" struct selabel_handle* selinux_android_service_context_handle(void) {
    return nullptr;
}
extern "C" int selinux_log_callback(int type, const char *fmt, ...) {
    (void) type;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    return 0;
}
extern "C" int selinux_status_open(int fallback) {
    (void) fallback;
    return STDIN_FILENO;
}
extern "C" int selinux_status_updated() {
    return false;
}
extern "C" int selinux_check_access(const char * scon, const char * tcon, const char *tclass, const char *perm, void *auditdata) {
    printf("CHECK ACCESS: %s %s %s %s", scon, tcon, tclass, perm);
    (void) auditdata;
    return 0;
}

#endif
