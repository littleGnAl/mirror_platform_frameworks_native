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

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>

#include <memory>

#ifdef __cplusplus

namespace android {

// Represents one strong pointer to an AIBinder object.
class AutoAIBinder {
public:
    // Takes ownership of one strong refcount of binder.
    explicit AutoAIBinder(AIBinder* binder = nullptr) : mBinder(binder) {}

    AutoAIBinder(const AutoAIBinder& other) { *this = other; }
    ~AutoAIBinder() { set(nullptr); }

    AutoAIBinder& operator=(const AutoAIBinder& other) {
        AIBinder_incStrong(other.mBinder);
        set(other.mBinder);
        return *this;
    }

    // Takes ownership of one strong refcount of binder
    void set(AIBinder* binder) {
        if (mBinder != nullptr) AIBinder_decStrong(mBinder);
        mBinder = binder;
    }

    AIBinder* get() { return mBinder; }
    AIBinder* release() {
        AIBinder* ret = mBinder;
        mBinder = nullptr;
        return ret;
    }

private:
    AIBinder* mBinder = nullptr;
};

template <typename T, void(*Destroy)(T**)>
class AutoA {
public:
    // Takes ownership of one strong refcount of T.
    explicit AutoA(T* t = nullptr) : mT(t, Destroy) {}
    T* get() { return mT.get(); }
private:
    std::unique_ptr<T*, decltype(Destroy)> mT;
};

typedef AutoA<AParcel, AParcel_delete> AutoAParcel;
// typedef AutoA<AStatus, AStatus_delete> AutoAStatus;
// typedef AutoA<ADeathRecipient, ADeathRecipient_delete> AutoADeathRecipient;
// typedef AutoADeathRecipient = std::unique_ptr<AParcel*, void(*)(AIBinder_DeathRecipient**)

} // namespace android

#endif // __cplusplus
