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

#include "AutoAIBinder.h"

#include <binder/AIBinder.h>
#include <utils/RefBase.h>

namespace android {

// wrapper analog to IInterface
class ICInterface : virtual RefBase {
public:
    ICInterface();
    virtual ~ICInterface();

    // Create or return the same representation
    virtual AutoAIBinder onAsBinder() = 0;
};

// wrapper analog to BnInterface
template <typename INTERFACE>
class BnCInterface : virtual INTERFACE {
public:
    BnCInterface() {}
    virtual ~BnCInterface() {}

    AutoAIBinder onAsBinder() override;

protected:
    virtual AutoAIBinder createBinder() = 0;

private:
    AWeak_AIBinder* mWeakBinder = nullptr;
};

// wrapper analog to BpInterfae
template <typename INTERFACE>
class BpCInterface : virtual INTERFACE {
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
        binder.set(AWeak_AIBinder_promote(mWeakBinder));
    }
    if (binder.get() == nullptr) {
        binder.set(createBinder());
        if (mWeakBinder != nullptr) {
            AWeak_AIBinder_delete(mWeakBinder);
        }
        mWeakBinder = AWeak_AIBinder_new(binder.get());
    }
    return binder;
}

template <typename I>
AutoAIBinder BpCInterface<I>::onAsBinder() {
    return mBinder;
}

} // namespace android
