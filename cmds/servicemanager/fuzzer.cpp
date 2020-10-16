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

#include <fuzzbinder/fuzzbinder.h>
#include "Access.h"
#include "ServiceManager.h"

class HostAccess : public android::Access {
public:
    HostAccess() {}
    virtual ~HostAccess() {}

    bool canFind(const CallingContext& ctx, const std::string& name) override {
        (void)ctx;
        return name.size() > 0 && name[0] % 2 == 0;
    }
    bool canAdd(const CallingContext& ctx, const std::string& name) override {
        (void)ctx;
        return name.size() > 0 && name[0] % 3 == 0;
    }
    bool canList(const CallingContext& ctx) override {
        (void)ctx;
        return true;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // avoid timeouts
    if (size > 50000) return 0;

#ifdef HOST_FUZZ
    auto access = std::make_unique<HostAccess>();
#else
    auto access = std::make_unique<android::Access>();
#endif
    android::sp<android::ServiceManager> manager = android::sp<android::ServiceManager>::make(std::move(access));
    android::fuzzBinder(manager, data, size);

    return 0;
}

#ifdef HOST_FUZZ

// These functions aren't implemented for selinux on host but SM uses them. Give
// emty implementations.

struct selabel_handle;
extern "C" struct selabel_handle* selinux_android_service_context_handle(void) {
    return nullptr;
}
extern "C" int selinux_log_callback(int type, const char *fmt, ...) {
    (void) type;
    (void) fmt;
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
    (void) scon;
    (void) tcon;
    (void) tclass;
    (void) perm;
    (void) auditdata;
    return 0;
}

#endif
