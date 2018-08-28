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

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>

#ifdef __cplusplus

namespace android {

// wrapper analog to IInterface
class ICInterface {
public:
    ICInterface() {}
    virtual ~ICInterface() {}

    // Create or return the same representation
    virtual AutoAIBinder onAsBinder() = 0;
};

// wrapper analog to BnInterface
template <typename INTERFACE>
class BnCInterface : public virtual INTERFACE {
public:
    BnCInterface() {}
    virtual ~BnCInterface() {}

    AutoAIBinder onAsBinder() override;

protected:
    virtual AutoAIBinder createBinder() = 0;

private:
    // FIXME: breaks copy/move constructors
    AIBinder_Weak* mWeakBinder = nullptr;
};

// wrapper analog to BpInterfae
template <typename INTERFACE>
class BpCInterface : public virtual INTERFACE {
public:
    BpCInterface(const AutoAIBinder& binder) : mBinder(binder) {}
    virtual ~BpCInterface() {}

    AutoAIBinder onAsBinder() override;

private:
    AutoAIBinder mBinder;
};

template <typename I>
AutoAIBinder BnCInterface<I>::onAsBinder() {
    AutoAIBinder binder;
    if (mWeakBinder != nullptr) {
        binder.set(AIBinder_Weak_promote(mWeakBinder));
    }
    if (binder.get() == nullptr) {
        binder = createBinder();
        if (mWeakBinder != nullptr) {
            AIBinder_Weak_delete(&mWeakBinder);
        }
        mWeakBinder = AIBinder_Weak_new(binder.get());
    }
    return binder;
}

template <typename I>
AutoAIBinder BpCInterface<I>::onAsBinder() {
    return mBinder;
}

#endif  // __cplusplus

} // namespace android
