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

// These are adapters from libbinder binder objects to the representation in libbinder_ndk. They
// also implement the protocol differences which are to be considered implementation details of
// libbinder and are not exposed to the NDK.

#include <binder/AIBinder.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>

namespace android {

class LocalNdkBinder : public BBinder {
public:
    void setAIBinder(wp<AIBinder> binder) { mBinder = binder; }
    wp<AIBinder> getAIBinder() { return mBinder; }

    const String16& getInterfaceDescriptor() const override;
    binder_status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                               binder_flags_t flags) override;

private:
    wp<AIBinder> mBinder;
};

binder_status_t initRemoteNdkBinderTransaction(const AIBinder* binder, AParcel* in);

} // namespace android
