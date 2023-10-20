/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android/binder_parcel.h>
#include <android/persistable_bundle.h>
#include <sys/cdefs.h>

namespace aidl::android::os {

/**
 * Wrapper class that enables interop with AIDL NDK generation
 * Takes ownership of the APersistableBundle* given to it in reset() and will automatically
 * destroy it in the destructor, similar to a smart pointer container
 */
class PersistableBundle {
   public:
    PersistableBundle() noexcept : mPBundle(APersistableBundle_new()) {}
    PersistableBundle(PersistableBundle&& other) noexcept : mPBundle(other.release()) {}
    PersistableBundle(const PersistableBundle& other) {
        mPBundle = APersistableBundle_dup(other.mPBundle);
    }
    PersistableBundle& operator=(const PersistableBundle& other) {
        mPBundle = APersistableBundle_dup(other.mPBundle);
        return *this;
    }

    ~PersistableBundle() { reset(); }

    binder_status_t readFromParcel(const AParcel* _Nonnull parcel) {
        reset();
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_readFromParcel(parcel, &mPBundle);
        } else {
            return STATUS_FAILED_TRANSACTION;
        }
    }

    binder_status_t writeToParcel(AParcel* _Nonnull parcel) const {
        if (!mPBundle) {
            return STATUS_BAD_VALUE;
        }
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_writeToParcel(mPBundle, parcel);
        } else {
            return STATUS_FAILED_TRANSACTION;
        }
    }

    /**
     * Destroys any currently owned APersistableBundle* and takes ownership of the given
     * APersistableBundle*
     *
     * @param pBundle The APersistableBundle to take ownership of
     */
    void reset(APersistableBundle* _Nullable pBundle = nullptr) noexcept {
        if (mPBundle) {
            APersistableBundle_delete(mPBundle);
            mPBundle = nullptr;
        }
        mPBundle = pBundle;
    }

    inline bool operator==(const PersistableBundle& rhs) const {
        return APersistableBundle_isEqual(get(), rhs.get());
    }
    inline bool operator!=(const PersistableBundle& rhs) const {
        return !APersistableBundle_isEqual(get(), rhs.get());
    }

    PersistableBundle& operator=(PersistableBundle&& other) noexcept {
        reset(other.release());
        return *this;
    }

    /**
     * Stops managing any contained APersistableBundle*, returning it to the caller. Ownership
     * is released.
     * @return APersistableBundle* or null if this was empty
     */
    [[nodiscard]] APersistableBundle* _Nullable release() noexcept {
        APersistableBundle* _Nullable ret = mPBundle;
        mPBundle = nullptr;
        return ret;
    }

    inline std::string toString() const {
        if (!mPBundle) {
            return "<PersistableBundle: Invalid>";
        }
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return "<PersistableBundle>";  // FIXME
        } else {
            return "<PersistableBundle (unknown)>";
        }
    }
    size_t size() const { return APersistableBundle_size(mPBundle); }
    size_t erase(const std::string& key) { return APersistableBundle_erase(mPBundle, key); }
    void putBoolean(const std::string& key, bool val) {
        APersistableBundle_putBoolean(mPBundle, key, val);
    }

   private:
    inline APersistableBundle* _Nullable get() const { return mPBundle; }
    APersistableBundle* _Nullable mPBundle = nullptr;
};

}  // namespace aidl::android::os
