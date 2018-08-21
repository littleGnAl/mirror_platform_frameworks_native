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

#include "NdkBinder.h"

#include "AIBinder_internal.h"
#include "AParcel_internal.h"

#include <android-base/logging.h>

namespace android {

const String16& LocalNdkBinder::getInterfaceDescriptor() const {
    return mBinder->getClass()->getInterfaceDescriptor();
}

binder_status_t LocalNdkBinder::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                           uint32_t flags) {
    if (code >= FIRST_CALL_TRANSACTION && code < LAST_CALL_TRANSACTION) {
        if (!data.checkInterface(this)) {
            return EX_ILLEGAL_STATE;
        }

        const AParcel in = AParcel::readOnly(&data);
        AParcel out = AParcel(reply, false /*owns*/);

        return mBinder->getClass()->onTransact(code, mBinder, &in, &out);
    } else {
        return BBinder::onTransact(code, data, reply, flags);
    }
}

binder_status_t initRemoteNdkBinderTransaction(const AIBinder* binder, AParcel* in) {
    const AIBinder_Class* clazz = binder->getClass();

    if (clazz == nullptr) {
        LOG(ERROR)
                << "Class must be defined for a remote binder transaction. See AIBinder_setClass.";
        return EX_ILLEGAL_STATE;
    }

    return (*in)->writeInterfaceToken(clazz->getInterfaceDescriptor());
}

} // namespace android