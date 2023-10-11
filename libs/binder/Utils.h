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

#pragma once

#include <stddef.h>
#include <sys/uio.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

#include <log/log.h>
#include <utils/Errors.h>

#define TEST_AND_RETURN(value, expr)            \
    do {                                        \
        if (!(expr)) {                          \
            ALOGE("Failed to call: %s", #expr); \
            return value;                       \
        }                                       \
    } while (0)

namespace android {

// avoid optimizations
void zeroMemory(uint8_t* data, size_t size);

// View of contiguous sequence. Similar to std::span.
template <typename T>
struct Span {
    T* data = nullptr;
    size_t size = 0;

    size_t byteSize() { return size * sizeof(T); }

    iovec toIovec() { return {const_cast<std::remove_const_t<T>*>(data), byteSize()}; }

    // Truncates `this` to a length of `offset` and returns a span with the
    // remainder.
    //
    // `std::nullopt` iff offset > size.
    std::optional<Span<T>> splitOff(size_t offset) {
        if (offset > size) {
            return std::nullopt;
        }
        Span<T> rest = {data + offset, size - offset};
        size = offset;
        return rest;
    }

    // Returns nullopt if the byte size of `this` isn't evenly divisible by sizeof(U).
    template <typename U>
    std::optional<Span<U>> reinterpret() const {
        // Only allow casting from bytes for simplicity.
        static_assert(std::is_same_v<std::remove_const_t<T>, uint8_t>);
        if (size % sizeof(U) != 0) {
            return std::nullopt;
        }
        return Span<U>{reinterpret_cast<U*>(data), size / sizeof(U)};
    }
};

// Converts binary data into a hexString.
//
// Hex values are printed in order, e.g. 0xDEAD will result in 'adde' because
// Android is little-endian.
std::string HexString(const void* bytes, size_t len);

template <typename F>
constexpr void assert_small_callable() {
    // While this buffer (std::function::__func::__buf_) is an implementation detail generally not
    // accessible to users, it's a good bet to assume its size to be around 3 pointers.
    constexpr size_t kFunctionBufferSize = 3 * sizeof(void*);

    static_assert(sizeof(F) <= kFunctionBufferSize,
                  "Supplied callable is larger than std::function optimization buffer. "
                  "Try using std::ref, but make sure lambda lives long enough to be called.");
}

template <typename F>
std::unique_ptr<void, std::function<void(void*)>> make_scope_guard(F&& f) {
    assert_small_callable<decltype(std::bind(f))>();
    return {reinterpret_cast<void*>(true), std::bind(f)};
}

template <typename T>
class SmallFunction : public std::function<T> {
public:
    template <typename F>
    SmallFunction(F&& f) : std::function<T>(f) {
        assert_small_callable<F>();
    }
};

}   // namespace android
