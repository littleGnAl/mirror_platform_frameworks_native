/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "ServiceManagerHost.h"
namespace android {

binder::Status ServiceManagerHost::getService(const std::string&, sp<IBinder>*) {
    // TODO(b/182914638): check VINTF properly.
    return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
}

binder::Status ServiceManagerHost::checkService(const std::string&, sp<IBinder>*) {
    return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
}
} // namespace android
