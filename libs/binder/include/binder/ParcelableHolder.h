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

#include <android-base/strings.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <optional>
#include <tuple>

namespace {
inline std::string toJavaClassName(const std::string& str) {
    std::string javaStyle = android::base::StringReplace(str, "::", ".", true);
    if (android::base::StartsWith(javaStyle, ".")) {
        return javaStyle.substr(1);
    }
    return javaStyle;
}
} // namespace

namespace android {
namespace os {
/*
 * C++ implementation of the Java class android.os.ParcelableHolder
 */
class ParcelableHolder : public android::Parcelable {
public:
    ParcelableHolder() = delete;
    explicit ParcelableHolder(Stability stability) : mStability(stability){};
    virtual ~ParcelableHolder() = default;
    ParcelableHolder(const ParcelableHolder& other) {
        mParcelable = other.mParcelable;
        mParcelableName = other.mParcelableName;
        if (other.mParcelPtr) {
            mParcelPtr = std::make_unique<Parcel>();
            mParcelPtr->appendFrom(other.mParcelPtr.get(), 0, other.mParcelPtr->dataSize());
        }
        mStability = other.mStability;
    };

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

    void reset() {
        this->mParcelable = nullptr;
        this->mParcelableName.reset();
        this->mParcelPtr.reset();
    }

    template <typename T>
    bool setParcelable(
            const T& p,
            const std::string& fullClassName /* TODO(b/157435345) remove this argument */) {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        if (this->getStability() > p.getStability()) {
            return false;
        }
        std::string javaClassName = toJavaClassName(fullClassName);
        this->mParcelable = std::make_shared<T>(p);
        this->mParcelableName = javaClassName;
        this->mParcelPtr.reset();
        return true;
    }

    template <typename T>
    bool setParcelable(
            std::shared_ptr<T>& p,
            const std::string& fullClassName /* TODO(b/157435345) remove this argument */) {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        if (p && this->getStability() > p->getStability()) {
            return false;
        }
        std::string javaClassName = toJavaClassName(fullClassName);
        this->mParcelable = p;
        this->mParcelableName = javaClassName;
        this->mParcelPtr.reset();
        return true;
    }

    template <typename T>
    std::shared_ptr<T> getParcelable(
            const std::string& fullClassName /* TODO(b/157435345) remove this argument */) const {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        std::string javaClassName = toJavaClassName(fullClassName);
        if (!this->mParcelPtr) {
            if (!this->mParcelable || !this->mParcelableName) {
                ALOGD("empty ParcelableHolder");
                return nullptr;
            } else if (javaClassName != *mParcelableName) {
                ALOGD("extension class name mismatch expected:%s actual:%s",
                      mParcelableName->c_str(), javaClassName.c_str());
                return nullptr;
            }
            return std::shared_ptr<T>(mParcelable, reinterpret_cast<T*>(mParcelable.get()));
        }
        this->mParcelPtr->setDataPosition(0);
        this->mParcelPtr->readUtf8FromUtf16(&this->mParcelableName);
        if (javaClassName != this->mParcelableName) {
            return nullptr;
        }
        this->mParcelable = std::make_shared<T>();
        mParcelable.get()->readFromParcel(this->mParcelPtr.get());
        this->mParcelPtr.reset();
        return std::shared_ptr<T>(mParcelable, reinterpret_cast<T*>(mParcelable.get()));
    }

    Stability getStability() const override { return mStability; };

    inline bool operator!=(const ParcelableHolder& rhs) const {
        return std::tie(mParcelable, mParcelPtr, mStability) !=
                std::tie(rhs.mParcelable, rhs.mParcelPtr, rhs.mStability);
    }
    inline bool operator<(const ParcelableHolder& rhs) const {
        return std::tie(mParcelable, mParcelPtr, mStability) <
                std::tie(rhs.mParcelable, rhs.mParcelPtr, rhs.mStability);
    }
    inline bool operator<=(const ParcelableHolder& rhs) const {
        return std::tie(mParcelable, mParcelPtr, mStability) <=
                std::tie(rhs.mParcelable, rhs.mParcelPtr, rhs.mStability);
    }
    inline bool operator==(const ParcelableHolder& rhs) const {
        return std::tie(mParcelable, mParcelPtr, mStability) ==
                std::tie(rhs.mParcelable, rhs.mParcelPtr, rhs.mStability);
    }
    inline bool operator>(const ParcelableHolder& rhs) const {
        return std::tie(mParcelable, mParcelPtr, mStability) >
                std::tie(rhs.mParcelable, rhs.mParcelPtr, rhs.mStability);
    }
    inline bool operator>=(const ParcelableHolder& rhs) const {
        return std::tie(mParcelable, mParcelPtr, mStability) >=
                std::tie(rhs.mParcelable, rhs.mParcelPtr, rhs.mStability);
    }

private:
    mutable std::shared_ptr<Parcelable> mParcelable;
    mutable std::optional<std::string> mParcelableName;
    mutable std::unique_ptr<Parcel> mParcelPtr;
    Stability mStability;
};
} // namespace os
} // namespace android
