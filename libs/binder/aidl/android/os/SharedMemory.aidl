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

package android.os;

/**
 * A shared memory region.
 *
 * This type contains the required information to share a region of memory between processes over
 * AIDL. An invalid (null) region may be represented using a null (-1) file descriptor.
 *
 * @hide
 */
parcelable SharedMemory {
    /** File descriptor of the memory region. */
    FileDescriptor fd;
    /** Offset, in bytes within the file of the start of the region. */
    int offset;
    /** Size, in bytes of the memory region. */
    int size;
}
