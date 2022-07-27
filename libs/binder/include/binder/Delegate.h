/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <binder/IBinder.h>

namespace android {

template <typename T>
sp<IBinder> delegateMakeFunc(void* args) {
    return sp<IBinder>::cast(
            sp<typename T::DefaultDelegator>::make(sp<T>::fromExisting(static_cast<T*>(args))));
}

template <typename T>
sp<T> delegate(const sp<T>& binder, const void* isDelegatorId, const void* hasDelegatorId) {
    // is binder itself a delegator?
    if (void* found = T::asBinder(binder)->findObject(isDelegatorId)) {
        // unwrap the delegator
        return sp<typename T::DefaultDelegator>::cast(binder)->getImpl();
    }

    // the binder is not a delegator, so construct one
    sp<IBinder> delegate =
            T::asBinder(binder)->lookupOrCreateWeak(hasDelegatorId, delegateMakeFunc<T>,
                                                    binder.get());
    // make sure we know this binder is a delegator by attaching a uniqueu ID
    (void)delegate->attachObject(isDelegatorId, reinterpret_cast<void*>(0x1), nullptr, nullptr);
    return sp<typename T::DefaultDelegator>::cast(delegate);
}

} // namespace android
