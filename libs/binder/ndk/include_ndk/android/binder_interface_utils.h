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

    virtual AutoAIBinder asBinder() = 0;
};

// wrapper analog to BnInterface
template <typename INTERFACE>
class BnCInterface : public virtual INTERFACE {
public:
    BnCInterface() {}
    virtual ~BnCInterface() {}

    AutoAIBinder asBinder() override;

protected:
    // FIXME: thread safety
    // Create or return the same representation
    virtual AutoAIBinder createBinder() = 0;

private:
    AutoAIBinder_Weak mWeakBinder;
};

// wrapper analog to BpInterfae
template <typename INTERFACE>
class BpCInterface : public virtual INTERFACE {
public:
    BpCInterface(const AutoAIBinder& binder) : mBinder(binder) {}
    virtual ~BpCInterface() {}

    AutoAIBinder asBinder() override;

private:
    AutoAIBinder mBinder;
};

template <typename I>
AutoAIBinder BnCInterface<I>::asBinder() {
    AutoAIBinder binder;
    if (mWeakBinder.get() != nullptr) {
        binder.set(AIBinder_Weak_promote(mWeakBinder.get()));
    }
    if (binder.get() == nullptr) {
        binder = createBinder();
        mWeakBinder.set(AIBinder_Weak_new(binder.get()));
    }
    return binder;
}

template <typename I>
AutoAIBinder BpCInterface<I>::asBinder() {
    return mBinder;
}

#endif // __cplusplus

} // namespace android
