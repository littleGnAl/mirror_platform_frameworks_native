/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <ui/DisplayInfo.h>

namespace android {

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-reinterpret-cast"
#endif

size_t DisplayInfo::getFlattenedSize() const {
    return sizeof(uint32_t) * 2 +  // w, h
           sizeof(float) * 4 +     // xdpi, ydpi, fps, density
           sizeof(uint32_t) +      // orientation(low 16 bits), secure(high 16 bits)
           sizeof(nsecs_t) * 2;    // appVsyncOffset, presentationDeadline
}

status_t DisplayInfo::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    uint32_t* const buf = static_cast<uint32_t*>(buffer);
    buf[0] = w;
    buf[1] = h;
    reinterpret_cast<float&>(buf[2]) = xdpi;
    reinterpret_cast<float&>(buf[3]) = ydpi;
    reinterpret_cast<float&>(buf[4]) = fps;
    reinterpret_cast<float&>(buf[5]) = density;
    buf[6] = (static_cast<uint32_t>(orientation) | static_cast<uint32_t>(secure) << 16);
    buf[7] = static_cast<uint32_t>(appVsyncOffset & 0xFFFFFFFFll);
    buf[8] = static_cast<uint32_t>(appVsyncOffset >> 32);
    buf[9] = static_cast<uint32_t>(presentationDeadline & 0xFFFFFFFFll);
    buf[10] = static_cast<uint32_t>(presentationDeadline >> 32);

    return NO_ERROR;
}

status_t DisplayInfo::unflatten(void const* buffer, size_t size) {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    uint32_t const* buf = static_cast<uint32_t const*>(buffer);

    w                    = buf[0];
    h                    = buf[1];
    xdpi                 = reinterpret_cast<float const&>(buf[2]);
    ydpi                 = reinterpret_cast<float const&>(buf[3]);
    fps                  = reinterpret_cast<float const&>(buf[4]);
    density              = reinterpret_cast<float const&>(buf[5]);
    orientation          = static_cast<uint8_t>(buf[6] & 0xFF);
    secure               = static_cast<bool>(buf[6] >> 16);
    appVsyncOffset       = (static_cast<nsecs_t>(buf[7]) | static_cast<nsecs_t>(buf[8])  << 32);
    presentationDeadline = (static_cast<nsecs_t>(buf[9]) | static_cast<nsecs_t>(buf[10]) << 32);

    return NO_ERROR;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

} // namespace android
