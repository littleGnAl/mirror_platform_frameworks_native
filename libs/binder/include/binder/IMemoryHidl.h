/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef ANDROID_IMEMORYHIDL_H
#define ANDROID_IMEMORYHIDL_H

#include <binder/IMemory.h>
#include <hidl/HidlSupport.h>

namespace android {

sp<::android::hardware::HidlMemory> toHidl(const sp<IMemoryHeap>& heap);

sp<IMemoryHeap> toBinder(const ::android::hardware::hidl_memory& mem);

sp<IMemory> toBinder(const ::android::hardware::hidl_memory_block& memblk);

//@return memblk.token == nullptr if it fails.
::android::hardware::hidl_memory_block toHidl(const sp<IMemory>& memory);

// ----------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_IMEMORY_H
