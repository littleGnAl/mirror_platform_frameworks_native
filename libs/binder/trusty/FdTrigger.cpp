/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "FdTrigger"
#include <log/log.h>

#include "../FdTrigger.h"

#include <android-base/macros.h>

namespace android {

std::unique_ptr<FdTrigger> FdTrigger::make() {
    auto ret = std::make_unique<FdTrigger>();
    return ret;
}

void FdTrigger::trigger() {}

bool FdTrigger::isTriggered() {
    return false;
}

status_t FdTrigger::triggerablePoll(base::borrowed_fd fd, int16_t event) {
    LOG_ALWAYS_FATAL_IF(event == 0, "triggerablePoll %d with event 0 is not allowed", fd.get());
    return OK;
}

} // namespace android
