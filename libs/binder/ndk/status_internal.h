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

#pragma once

#include <android/binder_status.h>

#include <binder/Status.h>
#include <utils/Errors.h>

namespace BinderStatus {

// Positive is interpreted as a service-specific error
binder_status_t FromStatusT(android::status_t status);

// You should never pass EX_REPLY_TRANSACTION through here. It will be converted to
// STATUS_UNKNOWN_ERROR. The Status object should be used to properly transform that value.
binder_status_t FromException(int32_t exception);

// TODO(b/115654595): libbinder shouldn't mix these together. When this is fixed, remove this
// function.
binder_status_t FromMixed(int32_t mixedValue);
int32_t ToMixed(binder_status_t status);

::android::binder::Status Unpack(binder_status_t binderStatus);

} // namespace BinderStatus
