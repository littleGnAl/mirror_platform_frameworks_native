/*
 * Copyright 2022 The Android Open Source Project
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

/**
 * @file hardware_buffer_aidl.h
 * @brief HardwareBuffer NDK AIDL glue code
 */

/**
 * @addtogroup AHardwareBuffer
 *
 * Parcelable support for AHardwareBuffer. Can be used with libbinder_ndk
 *
 * @{
 */

#ifndef ANDROID_HARDWARE_BUFFER_AIDL_H
#define ANDROID_HARDWARE_BUFFER_AIDL_H

#include <android/binder_parcel.h>
#include <android/hardware_buffer.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * Read an AHardwareBuffer from a AParcel.
 *
 * Available since API level 34.
 *
 * \return STATUS_OK on success
 */
binder_status_t AHardwareBuffer_readFromParcel(const AParcel* _Nonnull parcel,
        AHardwareBuffer* _Nullable* _Nonnull outBuffer) __INTRODUCED_IN(34);

/**
 * Write an AHardwareBuffer to an AParcel.
 *
 * Available since API level 34.
 *
 * \return STATUS_OK on success
 */
binder_status_t AHardwareBuffer_writeToParcel(const AHardwareBuffer* _Nonnull buffer,
        AParcel* _Nonnull parcel) __INTRODUCED_IN(34);

__END_DECLS

// Only enable the AIDL glue helper if this is C++
#ifdef __cplusplus

namespace aidl::android::hardware {

class HardwareBuffer {
public:
    HardwareBuffer() {}
    explicit HardwareBuffer(HardwareBuffer&& other) : mBuffer(other.release()) {}

    ~HardwareBuffer() {
        reset();
    }

    binder_status_t readFromParcel(const AParcel* _Nonnull parcel) {
        reset();
        return AHardwareBuffer_readFromParcel(parcel, &mBuffer);
    }

    binder_status_t writeToParcel(AParcel* _Nonnull parcel) const {
        if (!mBuffer) {
            return STATUS_BAD_VALUE;
        }
        return AHardwareBuffer_writeToParcel(mBuffer, parcel);
    }

    void reset(AHardwareBuffer* _Nullable buffer = nullptr) {
        if (mBuffer) {
            AHardwareBuffer_release(mBuffer);
            mBuffer = nullptr;
        }
        mBuffer = buffer;
    }

    inline AHardwareBuffer* _Nullable operator-> () const { return mBuffer;  }
    inline AHardwareBuffer* _Nullable get() const { return mBuffer; }
    inline explicit operator bool () const { return mBuffer != nullptr; }

    HardwareBuffer& operator=(HardwareBuffer&& other) {
        reset(other.release());
        return *this;
    }

    [[nodiscard]] AHardwareBuffer* _Nullable release() {
        AHardwareBuffer* _Nullable ret = mBuffer;
        mBuffer = nullptr;
        return ret;
    }

private:
    HardwareBuffer(const HardwareBuffer& other) = delete;
    HardwareBuffer& operator=(const HardwareBuffer& other) = delete;

    AHardwareBuffer* _Nullable mBuffer = nullptr;
};

} // aidl::android::hardware

#endif // __cplusplus

#endif // ANDROID_HARDWARE_BUFFER_AIDL_H

/** @} */
