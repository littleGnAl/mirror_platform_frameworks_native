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

#include <android/hidl/memory/1.1/IMapper.h>
#include <binder/IMemory.h>
#include <hidl/HidlSupport.h>
namespace android {

::android::hardware::HidlMemory toHidl(const sp<IMemoryHeap>& heap);

sp<IMemoryHeap> toBinder(const hardware::hidl_memory& mem);

sp<IMemory> toBinder(const ::android::hidl::memory::V1_1::memblk& memblk);

/**
 *  The IMemory object must be kept alive for any derived memblks to work.
 *  @return memblk.heapID = -1 if it fails.
 */
::android::hidl::memory::V1_1::memblk toHidl(const sp<IMemory>& memory);

// ----------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_IMEMORY_H
