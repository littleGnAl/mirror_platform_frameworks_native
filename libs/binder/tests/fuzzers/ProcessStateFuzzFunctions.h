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

#ifndef PROCESSSTATE_FUZZER_FUNCTIONS_H_
#define PROCESSSTATE_FUZZER_FUNCTIONS_H_

#include <binder/Binder.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <unordered_map>

#define PROCESSSTATE_MAX_DRIVER_LEN 256
#define PROCESSSTATE_MAXBUF_SIZE 2048
#define PROCESSSTATE_MAX_HANDLE 0x800000
#define PROCESSSTATE_MAX_KERNELREF_COUNT 4096
#define PROCESSSTATE_MAX_THREADS 50
#define DEFAULT_MAX_BINDER_THREADS 15 // This is defined in ProcessState.cpp

namespace android {

bool threadPoolStarted = false;
size_t threadPoolSize = DEFAULT_MAX_BINDER_THREADS;
std::unordered_map<uint32_t, sp<IBinder>> handleMap;

extern sp<ProcessState> gProcess;
void ProcessStateFuzzCleanup() {
    sp<ProcessState> ps = ProcessState::selfOrNull();
    if (ps != nullptr) {
        for (std::pair<uint32_t, sp<IBinder>> element : handleMap) {
            ps->expungeHandle(element.first, element.second.get());
        }
    }
    handleMap.clear();

    gProcess.clear();
    threadPoolStarted = false;
    threadPoolSize = DEFAULT_MAX_BINDER_THREADS;
}

bool callbackRetVal = false;
bool context_check_func(const String16& /*name*/, const sp<IBinder>& /*caller*/,
                        void* /*userData*/) {
    return callbackRetVal;
}

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*)>> processState_operations = {
        // self()
        [](FuzzedDataProvider*) -> void { ProcessState::self(); },

        // selfOrNull()
        [](FuzzedDataProvider*) -> void { ProcessState::selfOrNull(); },

        // NOTE: Omitting this function, as the library will LOG_ALWAYS_FATAL()
        //       on accessible but non-binder driver files, or the current
        //       driver path.
        // // initWithDriver(const char *driver)
        // [](FuzzedDataProvider* fdp) -> void {
        //   std::string driverStr =
        //       fdp->ConsumeRandomLengthString(PROCESSSTATE_MAX_DRIVER_LEN);
        //   // If driver matches the current driver, the function will trigger a
        //   // LOG_ALWAYS_FATAL()
        //   if(!gProcess ||
        //       !strcmp(gProcess->getDriverName().c_str(), driverStr.c_str())) {
        //     ProcessState::initWithDriver(driverStr.c_str());
        //   }
        // },

        // getContextObject(const sp<IBinder>& caller)
        [](FuzzedDataProvider*) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                sp<IBinder> bbinder = new BBinder();
                sp<IBinder> retBBinder = ps->getContextObject(bbinder);
                if (retBBinder) {
                    handleMap.insert_or_assign(0, retBBinder);
                }
            }
        },

        // NOTE: Unfortunately there does not seem to be a way to teardown
        //       threads that have been started, so we are unable to fuzz
        //       this function
        // [](FuzzedDataProvider*) -> void {
        //     sp<ProcessState> ps = ProcessState::selfOrNull();
        //     if (ps != nullptr) {
        //         ps->startThreadPool();
        //         threadPoolStarted = true;
        //     }
        // },

        // becomeContextManager(context_check_func checkFunc, void* userData)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                std::vector<uint8_t> bytes = fdp->ConsumeBytes<uint8_t>(
                        fdp->ConsumeIntegralInRange<size_t>(0, PROCESSSTATE_MAXBUF_SIZE));
                callbackRetVal = fdp->ConsumeBool();
                ps->becomeContextManager(context_check_func, bytes.data());
            }
        },

        // getStrongProxyForHandle(int32_t handle)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                // We're limiting this to positive values as it'll fail an overflow
                // check otherwise. As android::Vector allocates a vector of size
                // handle, we're also limiting the maximum value to prevent oom.
                int32_t handle = fdp->ConsumeIntegralInRange<int32_t>(0, PROCESSSTATE_MAX_HANDLE);
                sp<IBinder> new_binder = ps->getStrongProxyForHandle(handle);
                if (new_binder) {
                    handleMap.insert_or_assign(handle, new_binder);
                }
            }
        },

        // expungeHandle(int32_t handle, IBinder* binder)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                sp<IBinder> bbinder = new BBinder();
                // We're limiting this to positive values as it'll fail an overflow
                // check otherwise. As android::Vector allocates a vector of size
                // handle, we're also limiting the maximum value to prevent oom.
                int32_t handle = fdp->ConsumeIntegralInRange<int32_t>(0, PROCESSSTATE_MAX_HANDLE);
                ps->expungeHandle(handle, bbinder.get());
            }
        },

        // NOTE: This does nothing without startThreadPool, which is omitted
        //       from fuzzing (See above note)
        // spawnPooledThread(bool isMain)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                ps->spawnPooledThread(fdp->ConsumeBool());
            }
        },

        // setThreadPoolMaxThreadCount(size_t maxThreads)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                size_t new_value = fdp->ConsumeIntegralInRange<size_t>(0, PROCESSSTATE_MAX_THREADS);
                // If the threadpool is started, we can only increase
                if (!threadPoolStarted || new_value >= threadPoolSize) {
                    if (ps->setThreadPoolMaxThreadCount(new_value) == NO_ERROR) {
                        threadPoolSize = new_value;
                    }
                }
            }
        },

        // giveThreadPoolName()
        [](FuzzedDataProvider*) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                ps->giveThreadPoolName();
            }
        },

        // getDriverName()
        [](FuzzedDataProvider*) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                ps->getDriverName();
            }
        },

        // getKernelReferences(size_t count, uintptr_t* buf)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                size_t count =
                        fdp->ConsumeIntegralInRange<size_t>(0, PROCESSSTATE_MAX_KERNELREF_COUNT);
                uintptr_t* buf = static_cast<uintptr_t*>(malloc(count * sizeof(uintptr_t)));
                if (buf) {
                    ps->getKernelReferences(count, buf);
                    free(buf);
                }
            }
        },

        // getStrongRefCountForNodeByHandle(int32_t handle)
        [](FuzzedDataProvider* fdp) -> void {
            sp<ProcessState> ps = ProcessState::selfOrNull();
            if (ps != nullptr) {
                // We're limiting this to positive values as it'll fail an overflow
                // check otherwise. As android::Vector allocates a vector of size
                // handle, we're also limiting the maximum value to prevent oom.
                int32_t handle = fdp->ConsumeIntegralInRange<int32_t>(0, PROCESSSTATE_MAX_HANDLE);
                ps->getStrongRefCountForNodeByHandle(handle);
            }
        },

        // setCallRestriction(CallRestriction restriction)
        [](FuzzedDataProvider* fdp) -> void {
            // This will throw a LOG_ALWAYS_FATAL if IPCThreadState is initialized.
            if (IPCThreadState::selfOrNull() == nullptr) {
                sp<ProcessState> ps = ProcessState::selfOrNull();
                if (ps != nullptr) {
                    ProcessState::CallRestriction cr;
                    switch (fdp->ConsumeIntegralInRange(0, 2)) {
                        case 0:
                            cr = ProcessState::CallRestriction::NONE;
                            break;
                        case 1:
                            cr = ProcessState::CallRestriction::ERROR_IF_NOT_ONEWAY;
                            break;
                        case 2:
                            cr = ProcessState::CallRestriction::FATAL_IF_NOT_ONEWAY;
                            break;
                    }
                    ps->setCallRestriction(cr);
                }
            }
        }};
} // namespace android

#endif // PROCESSSTATE_FUZZER_FUNCTIONS_H_
