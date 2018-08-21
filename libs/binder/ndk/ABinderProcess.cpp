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

#include <binder/ABinderProcess.h>

#include <mutex>

#include <binder/IPCThreadState.h>

using ::android::IPCThreadState;

// Binder driver connections to the kernel right now are singletons, so this is
// a placeholder for changes to this architecture.
struct ABinderProcess {};

std::mutex gBinderProcessPlaceholderMutex;
ABinderProcess gBinderProcessPlaceholder;
bool gThreadPoolCreated = false;

ABinderProcess* ABinderProcess_threadpool(uint32_t numThreads) {
    std::lock_guard<std::mutex> lock(gBinderProcessPlaceholderMutex);

    if (gThreadPoolCreated) {
        // FIXME: log
        return nullptr;
    }

    // FIXME: make sure it's not already created
    // FIXME: start threads
    (void)numThreads;
    return &gBinderProcessPlaceholder;
}

void ABinderProcess_join(ABinderProcess* p) {
    {
        std::lock_guard<std::mutex> lock(gBinderProcessPlaceholderMutex);

        if (p != &gBinderProcessPlaceholder) {
            return;
        }
    }

    IPCThreadState::self()->joinThreadPool();
}
