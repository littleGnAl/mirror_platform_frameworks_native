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

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/ParcelableHolder.h>

namespace android {
namespace os {
status_t ParcelableHolder::writeToParcel(Parcel* p) const {
    p->writeInt32(static_cast<int32_t>(this->getStability()));
    if (this->mParcelPtr) {
        p->writeInt32(this->mParcelPtr->dataSize());
        p->appendFrom(this->mParcelPtr.get(), 0, this->mParcelPtr->dataSize());
        return OK;
    }
    if (this->mParcelable) {
        size_t sizePos = p->dataPosition();
        p->writeInt32(0);
        size_t dataStartPos = p->dataPosition();
        p->writeUtf8AsUtf16(this->mParcelableName);
        this->mParcelable->writeToParcel(p);
        size_t dataSize = p->dataPosition() - dataStartPos;

        p->setDataPosition(sizePos);
        p->writeInt32(dataSize);
        p->setDataPosition(p->dataPosition() + dataSize);
        return OK;
    }

    p->writeInt32(0);
    return OK;
}

status_t ParcelableHolder::readFromParcel(const Parcel* p) {
    this->mStability = static_cast<Stability>(p->readInt32());
    this->mParcelable = nullptr;

    if (!this->mParcelPtr) {
        this->mParcelPtr = std::make_unique<Parcel>();
    }
    this->mParcelPtr->setDataPosition(0);
    this->mParcelPtr->setDataSize(0);

    size_t dataSize = p->readInt32();
    if (dataSize == 0) {
        this->mParcelPtr.reset();
        return OK;
    }
    if (dataSize < 0) {
        return BAD_VALUE;
    }
    size_t dataStartPos = p->dataPosition();

    this->mParcelPtr->appendFrom(p, dataStartPos, dataSize);
    p->setDataPosition(dataStartPos + dataSize);
    return OK;
}
} // namespace os
} // namespace android
