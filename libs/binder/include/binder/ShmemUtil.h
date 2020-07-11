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

#pragma once

// This module contains utilities for working with android.os.SharedFileRegion.

#include "android/os/SharedFileRegion.h"

namespace android {

/**
 * Checks whether a SharedFileRegion instance is valid (all the fields have sane values).
 * A null SharedFileRegion (having a negative FD) is considered valid.
 */
bool validateSharedFileRegion(const os::SharedFileRegion& shmem);

}  // namespace android
