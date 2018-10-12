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

/**
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_parcel_utils.h
 * @brief A collection of helper wrappers for AParcel.
 */

#pragma once

#include <android/binder_parcel.h>

#ifdef __cplusplus

#include <string>
#include <vector>

namespace ndk {

typedef void* (*AParcel_vector_reallocator)(void* vectorData, size_t length);

template <typename T>
static inline void* AParcel_std_vector_reallocator(void* vectorData, size_t length) {
    std::vector<T>* vec = static_cast<std::vector<T>*>(vectorData);
    if (length > vec->max_size()) return nullptr;

    vec->resize(length);
    return vec;
}

// @START
/**
 * This retrieves the underlying int32_t array from a corresponding vectorData.
 */
static inline int32_t* AParcel_int32_std_vector_getter(void* vectorData) {
    std::vector<int32_t>* vec = static_cast<std::vector<int32_t>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of int32_t to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeInt32Array(AParcel* parcel,
                                                      const std::vector<int32_t>& vec) {
    return AParcel_writeInt32Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of int32_t from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readInt32Array(const AParcel* parcel,
                                                     std::vector<int32_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readInt32Array(parcel, &vectorData, &AParcel_std_vector_reallocator<int32_t>,
                                  AParcel_int32_std_vector_getter);
}

/**
 * This retrieves the underlying uint32_t array from a corresponding vectorData.
 */
static inline uint32_t* AParcel_uint32_std_vector_getter(void* vectorData) {
    std::vector<uint32_t>* vec = static_cast<std::vector<uint32_t>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of uint32_t to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeUint32Array(AParcel* parcel,
                                                       const std::vector<uint32_t>& vec) {
    return AParcel_writeUint32Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of uint32_t from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readUint32Array(const AParcel* parcel,
                                                      std::vector<uint32_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readUint32Array(parcel, &vectorData, &AParcel_std_vector_reallocator<uint32_t>,
                                   AParcel_uint32_std_vector_getter);
}

/**
 * This retrieves the underlying int64_t array from a corresponding vectorData.
 */
static inline int64_t* AParcel_int64_std_vector_getter(void* vectorData) {
    std::vector<int64_t>* vec = static_cast<std::vector<int64_t>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of int64_t to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeInt64Array(AParcel* parcel,
                                                      const std::vector<int64_t>& vec) {
    return AParcel_writeInt64Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of int64_t from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readInt64Array(const AParcel* parcel,
                                                     std::vector<int64_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readInt64Array(parcel, &vectorData, &AParcel_std_vector_reallocator<int64_t>,
                                  AParcel_int64_std_vector_getter);
}

/**
 * This retrieves the underlying uint64_t array from a corresponding vectorData.
 */
static inline uint64_t* AParcel_uint64_std_vector_getter(void* vectorData) {
    std::vector<uint64_t>* vec = static_cast<std::vector<uint64_t>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of uint64_t to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeUint64Array(AParcel* parcel,
                                                       const std::vector<uint64_t>& vec) {
    return AParcel_writeUint64Array(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of uint64_t from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readUint64Array(const AParcel* parcel,
                                                      std::vector<uint64_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readUint64Array(parcel, &vectorData, &AParcel_std_vector_reallocator<uint64_t>,
                                   AParcel_uint64_std_vector_getter);
}

/**
 * This retrieves the underlying float array from a corresponding vectorData.
 */
static inline float* AParcel_float_std_vector_getter(void* vectorData) {
    std::vector<float>* vec = static_cast<std::vector<float>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of float to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeFloatArray(AParcel* parcel,
                                                      const std::vector<float>& vec) {
    return AParcel_writeFloatArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of float from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readFloatArray(const AParcel* parcel,
                                                     std::vector<float>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readFloatArray(parcel, &vectorData, &AParcel_std_vector_reallocator<float>,
                                  AParcel_float_std_vector_getter);
}

/**
 * This retrieves the underlying double array from a corresponding vectorData.
 */
static inline double* AParcel_double_std_vector_getter(void* vectorData) {
    std::vector<double>* vec = static_cast<std::vector<double>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of double to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeDoubleArray(AParcel* parcel,
                                                       const std::vector<double>& vec) {
    return AParcel_writeDoubleArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of double from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readDoubleArray(const AParcel* parcel,
                                                      std::vector<double>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readDoubleArray(parcel, &vectorData, &AParcel_std_vector_reallocator<double>,
                                   AParcel_double_std_vector_getter);
}

/**
 * This retrieves the underlying value in a bool array at index  from a corresponding vectorData.
 */
static inline bool AParcel_bool_std_vector_getter(const void* vectorData, size_t index) {
    const std::vector<bool>* vec = static_cast<const std::vector<bool>*>(vectorData);
    return (*vec)[index];
}

/**
 * This sets the underlying bool in a corresponding vectorData.
 */
static inline void AParcel_bool_std_vector_setter(void* vectorData, size_t index, bool value) {
    std::vector<bool>* vec = static_cast<std::vector<bool>*>(vectorData);
    (*vec)[index] = value;
}

/**
 * Writes a vector of bool to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeBoolArray(AParcel* parcel,
                                                     const std::vector<bool>& vec) {
    return AParcel_writeBoolArray(parcel, static_cast<const void*>(&vec),
                                  AParcel_bool_std_vector_getter, vec.size());
}

/**
 * Reads a vector of bool from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readBoolArray(const AParcel* parcel, std::vector<bool>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readBoolArray(parcel, &vectorData, &AParcel_std_vector_reallocator<bool>,
                                 AParcel_bool_std_vector_setter);
}

/**
 * This retrieves the underlying char16_t array from a corresponding vectorData.
 */
static inline char16_t* AParcel_char_std_vector_getter(void* vectorData) {
    std::vector<char16_t>* vec = static_cast<std::vector<char16_t>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of char16_t to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeCharArray(AParcel* parcel,
                                                     const std::vector<char16_t>& vec) {
    return AParcel_writeCharArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of char16_t from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readCharArray(const AParcel* parcel,
                                                    std::vector<char16_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readCharArray(parcel, &vectorData, &AParcel_std_vector_reallocator<char16_t>,
                                 AParcel_char_std_vector_getter);
}

/**
 * This retrieves the underlying int8_t array from a corresponding vectorData.
 */
static inline int8_t* AParcel_byte_std_vector_getter(void* vectorData) {
    std::vector<int8_t>* vec = static_cast<std::vector<int8_t>*>(vectorData);
    return vec->data();
}

/**
 * Writes a vector of int8_t to the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_writeByteArray(AParcel* parcel,
                                                     const std::vector<int8_t>& vec) {
    return AParcel_writeByteArray(parcel, vec.data(), vec.size());
}

/**
 * Reads a vector of int8_t from the next location in a non-null parcel.
 */
static inline binder_status_t AParcel_readByteArray(const AParcel* parcel,
                                                    std::vector<int8_t>* vec) {
    void* vectorData = static_cast<void*>(vec);
    return AParcel_readByteArray(parcel, &vectorData, &AParcel_std_vector_reallocator<int8_t>,
                                 AParcel_byte_std_vector_getter);
}

// @END

/**
 * Takes a std::string and reallocates it to the specified length. For use with AParcel_readString.
 * See use below in AParcel_readString.
 */
static inline void* AParcel_std_string_reallocator(void* stringData, size_t length) {
    std::string* str = static_cast<std::string*>(stringData);
    str->resize(length - 1);
    return stringData;
}

/**
 * Takes a std::string and returns the inner char*.
 */
static inline char* AParcel_std_string_getter(void* stringData) {
    std::string* str = static_cast<std::string*>(stringData);
    return &(*str)[0];
}

/**
 * Convenience API for writing a std::string.
 */
static inline binder_status_t AParcel_writeString(AParcel* parcel, const std::string& str) {
    return AParcel_writeString(parcel, str.c_str(), str.size());
}

/**
 * Convenience API for reading a std::string.
 */
static inline binder_status_t AParcel_readString(const AParcel* parcel, std::string* str) {
    void* stringData = static_cast<void*>(str);
    return AParcel_readString(parcel, AParcel_std_string_reallocator, AParcel_std_string_getter,
                              &stringData);
}

} // namespace ndk

#endif // __cplusplus

/** @} */
