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

#include <binder/IPCThreadState.h>

namespace {

using namespace android;

// Initialize an IPCThreadState from the main thread, before anyone spins up a
// child thread and initializes thread-local state in binder. Doing this on the
// main thread is necessary so that when libbinder C++ static destructors are
// called, binder has an IPCThreadState already on the main thread. Trying to
// initialize a new IPCThreadstate inside the static destructors was causing
// non-deterministic segfaults, presumably due to use-after-free of static
// globals. This was observed because the Rust test harness always executes
// tests on a child thread while the C++ global static destructors run on the
// main thread.
IPCThreadState* init = IPCThreadState::self();

}; // anonymous namespace
