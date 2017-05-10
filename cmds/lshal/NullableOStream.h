/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef FRAMEWORK_NATIVE_CMDS_LSHAL_NULLABLE_O_STREAM_H_
#define FRAMEWORK_NATIVE_CMDS_LSHAL_NULLABLE_O_STREAM_H_

#include <iostream>

namespace android {
namespace lshal {

template<typename S>
class NullableOStream {
public:
    NullableOStream(S &os, bool restoreErrno = false) : mOs(&os), mRestoreErrno(restoreErrno) {}
    NullableOStream(S *os, bool restoreErrno = false) : mOs(os),  mRestoreErrno(restoreErrno) {}
    NullableOStream &operator=(S &os) {
        mOs = &os;
        return *this;
    }
    NullableOStream &operator=(S *os) {
        mOs = os;
        return *this;
    }
    template<typename Other>
    NullableOStream &operator=(const NullableOStream<Other> &other) {
        mOs = other.mOs;
        return *this;
    }

    const NullableOStream &operator<<(std::ostream& (*pf)(std::ostream&)) const {
        auto savedErrno = errno;
        if (mOs) {
            (*mOs) << pf;
        }
        if (mRestoreErrno) {
            errno = savedErrno;
        }
        return *this;
    }
    template<typename T>
    const NullableOStream &operator<<(const T &rhs) const {
        auto savedErrno = errno;
        if (mOs) {
            (*mOs) << rhs;
        }
        if (mRestoreErrno) {
            errno = savedErrno;
        }
        return *this;
    }
    S& buf() const {
        return *mOs;
    }
    operator bool() const {
        return mOs != nullptr;
    }
private:
    template<typename>
    friend class NullableOStream;

    S *mOs = nullptr;
    bool mRestoreErrno;
};

}  // namespace lshal
}  // namespace android

#endif  // FRAMEWORK_NATIVE_CMDS_LSHAL_NULLABLE_O_STREAM_H_
