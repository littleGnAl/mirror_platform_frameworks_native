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

#include <set>
#include <sstream>

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
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            mPBundle = APersistableBundle_dup(other.mPBundle);
        }
    }
    PersistableBundle& operator=(const PersistableBundle& other) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            mPBundle = APersistableBundle_dup(other.mPBundle);
        }
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
            if (__builtin_available(android __ANDROID_API_V__, *)) {
                APersistableBundle_delete(mPBundle);
            }
            mPBundle = nullptr;
        }
        mPBundle = pBundle;
    }

    inline bool operator==(const PersistableBundle& rhs) const {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_isEqual(get(), rhs.get());
        } else {
            return false;
        }
    }
    inline bool operator!=(const PersistableBundle& rhs) const {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return !APersistableBundle_isEqual(get(), rhs.get());
        } else {
            return true;
        }
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
        } else if (__builtin_available(android __ANDROID_API_V__, *)) {
            std::ostringstream os;
            os << "<PersistableBundle:";
            os << "size: " << std::to_string(APersistableBundle_size(mPBundle));
            // FIXME print all the things?
            os << ">";
            return os.str();
        }
        return "<PersistableBundle (unknown)>";
    }

    size_t size() const {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_size(mPBundle);
        } else {
            return 0;
        }
    }

    size_t erase(const std::string& key) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_erase(mPBundle, key.c_str());
        } else {
            return 0;
        }
    }

    void putBoolean(const std::string& key, bool val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            APersistableBundle_putBoolean(mPBundle, key.c_str(), val);
        }
    }

    void putInt(const std::string& key, int32_t val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            APersistableBundle_putInt(mPBundle, key.c_str(), val);
        }
    }

    void putLong(const std::string& key, int64_t val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            APersistableBundle_putLong(mPBundle, key.c_str(), val);
        }
    }

    void putDouble(const std::string& key, double val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            APersistableBundle_putDouble(mPBundle, key.c_str(), val);
        }
    }

    void putString(const std::string& key, const std::string& val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            APersistableBundle_putString(mPBundle, key.c_str(), val.c_str());
        }
    }

    void putBooleanVector(const std::string& key, const std::vector<bool>& vec) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            // std::vector<bool> has no ::data().
            size_t num = vec.size();
            if (num > 0) {
                bool* newVec = (bool*)malloc(num * sizeof(bool));
                if (newVec) {
                    for (size_t i = 0; i < num; i++) {
                        newVec[i] = vec[i];
                    }
                    APersistableBundle_putBooleanVector(mPBundle, key.c_str(), newVec, num);
                    free(newVec);
                }
            }
        }
    }

    bool getBoolean(const std::string& key, bool* _Nonnull val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_getBoolean(mPBundle, key.c_str(), val);
        } else {
            return false;
        }
    }

    bool getInt(const std::string& key, int32_t* _Nonnull val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_getInt(mPBundle, key.c_str(), val);
        } else {
            return false;
        }
    }

    bool getLong(const std::string& key, int64_t* _Nonnull val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_getLong(mPBundle, key.c_str(), val);
        } else {
            return false;
        }
    }

    bool getDouble(const std::string& key, double* _Nonnull val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_getDouble(mPBundle, key.c_str(), val);
        } else {
            return false;
        }
    }

    bool getString(const std::string& key, std::string* _Nonnull val) {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            char* outString = nullptr;
            bool ret = APersistableBundle_getString(mPBundle, key.c_str(), &outString);
            if (ret && outString) {
                *val = std::string(outString);
            }
            return ret;
        } else {
            return false;
        }
    }

    bool getBooleanVector(const std::string& key, std::vector<bool>* _Nonnull vec) {
        bool* newVec = nullptr;
        size_t num = 0;
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            num = APersistableBundle_getBooleanVector(mPBundle, key.c_str(), &newVec);
        }
        if (newVec && num > 0) {
            vec->clear();
            for (int i = 0; i < num; i++) {
                vec->push_back(newVec[i]);
            }
            free(newVec);
            return true;
        }
        return false;
    }

    // Takes ownership of and frees the char** and its elements.
    // Creates a new set based on the array of char*.
    std::set<std::string> getKeys(char* _Nonnull* _Nonnull keys, size_t num) {
        if (keys && num > 0) {
            std::set<std::string> ret;
            for (size_t i = 0; i < num; i++) {
                ret.emplace(keys[i]);
                free(keys[i]);
            }
            free(keys);
            return ret;
        }
        return {};
    }

    std::set<std::string> getBooleanKeys() {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            char** keys = nullptr;
            size_t num = APersistableBundle_getBooleanKeys(mPBundle, &keys);
            return getKeys(keys, num);
        } else {
            return {};
        }
    }
    std::set<std::string> getIntKeys() {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            char** keys = nullptr;
            size_t num = APersistableBundle_getIntKeys(mPBundle, &keys);
            return getKeys(keys, num);
        } else {
            return {};
        }
    }

    std::set<std::string> getLongKeys() {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            char** keys = nullptr;
            size_t num = APersistableBundle_getLongKeys(mPBundle, &keys);
            return getKeys(keys, num);
        } else {
            return {};
        }
    }

    std::set<std::string> getDoubleKeys() {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            char** keys = nullptr;
            size_t num = APersistableBundle_getDoubleKeys(mPBundle, &keys);
            return getKeys(keys, num);
        } else {
            return {};
        }
    }

    std::set<std::string> getStringKeys() {
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            char** keys = nullptr;
            size_t num = APersistableBundle_getStringKeys(mPBundle, &keys);
            return getKeys(keys, num);
        } else {
            return {};
        }
    }

   private:
    inline APersistableBundle* _Nullable get() const { return mPBundle; }
    APersistableBundle* _Nullable mPBundle = nullptr;
};

}  // namespace aidl::android::os
