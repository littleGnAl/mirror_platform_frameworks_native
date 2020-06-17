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

#include <android/binder_ibinder.h>

namespace {

// Make sure that we initialize an IPCThreadState for the main thread. Doing
// this on the main thread is necessary so that when libbinder C++ static
// destructors are called, binder has an IPCThreadState already initialized for
// the main thread. We don't care about the result of AIBinder_getCallingPid(),
// just that it calls IPCThreadstate::self() internally.
//
// Trying to initialize a new IPCThreadstate inside the static destructors
// causes non-deterministic segfaults depending on destructor ordering. If
// sp<ProcessState> gProcess is destroyed before static sp<IServiceManager>
// gDefaultServiceManager, the destructor for the latter will call
// IPCThreadState::self() which, if the thread does not already have a thread
// state object, will call ProcessState::self(). When gProcess is destroyed, its
// pointee is destroyed, but the sp reference itself is not zeroed out (because
// its destroyed, right?). When ProcessState::self() tries to grab the process
// state it just checks the strong pointer for NULL, and it isn't, so it uses
// the destroyed ProcessState object.
//
// This was observed because the Rust test harness always executes tests on a
// child thread while the C++ global static destructors run on the main thread,
// so the main thread didn't have an IPCThreadState already.
pid_t p = AIBinder_getCallingPid();

}; // anonymous namespace
