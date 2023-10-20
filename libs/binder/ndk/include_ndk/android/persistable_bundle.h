/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <android/binder_parcel.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

struct APersistableBundle;
typedef struct APersistableBundle APersistableBundle;

/**
 * This is a user supplied allocator that duplicates a given string.
 *
 * If allocation fails, null should be set for the outStr.
 *
 * \return true if the allocation succeeded, and false if it failed.
 */
typedef bool (*_Nonnull APersistableBundle_strDupAllocator)(char* _Nullable* _Nullable outStr,
                                                            size_t sizeBytes,
                                                            const char* _Nonnull inStr);

/**
 * Create a new APersistableBundle.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return Pointer to a new APersistableBundle
 */
APersistableBundle* _Nullable APersistableBundle_new() __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Create a new APersistableBundle based off an existing APersistableBundle.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return Pointer to a new APersistableBundle
 */
APersistableBundle* _Nullable APersistableBundle_dup(const APersistableBundle* _Nonnull pBundle)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Delete an APersistableBundle. This must always be called when finished using
 * the object.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_delete(APersistableBundle* _Nonnull pBundle)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Check for equality of APersistableBundles.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return true when equal, false when not
 */
bool APersistableBundle_isEqual(const APersistableBundle* _Nonnull lhs,
                                const APersistableBundle* _Nonnull rhs)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Read an APersistableBundle from an AParcel.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return STATUS_OK on success
 *         STATUS_BAD_VALUE if the parcel or outBuffer is null, or if there's an
 *                          issue deserializing (eg, corrupted parcel)
 *         STATUS_BAD_TYPE if the parcel's current data position is not that of
 *                         an APersistableBundle type
 *         STATUS_NO_MEMORY if an allocation fails
 */
binder_status_t APersistableBundle_readFromParcel(const AParcel* _Nonnull parcel,
                                                  APersistableBundle* _Nullable* _Nonnull outBuffer)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Write an APersistableBundle to an AParcel.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return STATUS_OK on success.
 *         STATUS_BAD_VALUE if either pBundle or parcel is null, or if the
 *         APersistableBundle*
 *                          fails to serialize (eg, internally corrupted)
 *         STATUS_NO_MEMORY if the parcel runs out of space to store the pBundle & is
 *                          unable to allocate more
 *         STATUS_FDS_NOT_ALLOWED if the parcel does not allow storing FDs
 */
binder_status_t APersistableBundle_writeToParcel(const APersistableBundle* _Nonnull pBundle,
                                                 AParcel* _Nonnull parcel)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get the size of an APersistableBundle. This is the number of mappings in the
 * object.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return number of mappings in the object
 */
size_t APersistableBundle_size(APersistableBundle* _Nonnull pBundle)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Erase any entries added with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return number of entries erased
 */
size_t APersistableBundle_erase(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put a boolean associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putBoolean(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                                   bool val) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put an int32_t associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putInt(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                               int32_t val) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put an int64_t associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putLong(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                                int64_t val) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put a double associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putDouble(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                                  double val) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put a string associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putString(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                                  const char* _Nonnull val) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put a boolean vector associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putBooleanVector(APersistableBundle* _Nonnull pBundle,
                                         const char* _Nonnull key, const bool* _Nonnull vec,
                                         size_t num) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put an int32_t vector associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putIntVector(APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                                     const int32_t* _Nonnull vec, size_t num)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put an int64_t vector associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putLongVector(APersistableBundle* _Nonnull pBundle,
                                      const char* _Nonnull key, const int64_t* _Nonnull vec,
                                      size_t num) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put a double vector associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putDoubleVector(APersistableBundle* _Nonnull pBundle,
                                        const char* _Nonnull key, const double* _Nonnull vec,
                                        size_t num) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put a string vector associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putStringVector(APersistableBundle* _Nonnull pBundle,
                                        const char* _Nonnull key,
                                        const char* _Nullable const* _Nullable vec, size_t num)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Put an APersistableBundle associated with the provided key.
 * New values with the same key will overwrite existing values.
 *
 * Available since API level __ANDROID_API_V__.
 */
void APersistableBundle_putPersistableBundle(APersistableBundle* _Nonnull pBundle,
                                             const char* _Nonnull key,
                                             const APersistableBundle* _Nonnull val)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get a boolean associated with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return true if a value exists for the provided key
 */
bool APersistableBundle_getBoolean(const APersistableBundle* _Nonnull pBundle,
                                   const char* _Nonnull key, bool* _Nonnull val)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get an int32_t associated with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return true if a value exists for the provided key
 */
bool APersistableBundle_getInt(const APersistableBundle* _Nonnull pBundle, const char* _Nonnull key,
                               int32_t* _Nonnull val) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get an int64_t associated with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return true if a value exists for the provided key
 */
bool APersistableBundle_getLong(const APersistableBundle* _Nonnull pBundle,
                                const char* _Nonnull key, int64_t* _Nonnull val)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get a double associated with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return true if a value exists for the provided key
 */
bool APersistableBundle_getDouble(const APersistableBundle* _Nonnull pBundle,
                                  const char* _Nonnull key, double* _Nonnull val)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get a string associated with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return size of string associated with the provided key on success
 *         0 if no string exists for the provided key
 *         -1 if the provided allocator fails and returns false
 */
ssize_t APersistableBundle_getString(const APersistableBundle* _Nonnull pBundle,
                                     const char* _Nonnull key, char* _Nullable* _Nonnull val,
                                     APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get a boolean vector associated with the provided key and place it in the
 * provided pre-allocated buffer from the user.
 *
 * This function returns the size in bytes of stored vector.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the stored vector in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 */
size_t APersistableBundle_getBooleanVector(const APersistableBundle* _Nonnull pBundle,
                                           const char* _Nonnull key, bool* _Nullable buffer,
                                           size_t bufferSizeBytes)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get an int32_t vector associated with the provided key and place it in the
 * provided pre-allocated buffer from the user.
 *
 * This function returns the size in bytes of stored vector.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the stored vector in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 */
size_t APersistableBundle_getIntVector(const APersistableBundle* _Nonnull pBundle,
                                       const char* _Nonnull key, int32_t* _Nullable buffer,
                                       size_t bufferSizeBytes) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get an int64_t vector associated with the provided key and place it in the
 * provided pre-allocated buffer from the user.
 *
 * This function returns the size in bytes of stored vector.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the stored vector in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 */
size_t APersistableBundle_getLongVector(const APersistableBundle* _Nonnull pBundle,
                                        const char* _Nonnull key, int64_t* _Nullable buffer,
                                        size_t bufferSizeBytes) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get a double vector associated with the provided key and place it in the
 * provided pre-allocated buffer from the user.
 *
 * This function returns the size in bytes of stored vector.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the stored vector in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 */
size_t APersistableBundle_getDoubleVector(const APersistableBundle* _Nonnull pBundle,
                                          const char* _Nonnull key, double* _Nullable buffer,
                                          size_t bufferSizeBytes)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get a string vector associated with the provided key and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes of stored vector.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the stored vector in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getStringVector(const APersistableBundle* _Nonnull pBundle,
                                           const char* _Nonnull key,
                                           char* _Nullable* _Nullable buffer,
                                           size_t bufferSizeBytes,
                                           APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get an APersistableBundle* associated with the provided key.
 *
 * Available since API level __ANDROID_API_V__.
 *
 * \return true if a value exists for the provided key
 */
bool APersistableBundle_getPersistableBundle(const APersistableBundle* _Nonnull pBundle,
                                             const char* _Nonnull key,
                                             APersistableBundle* _Nullable* _Nonnull outBundle)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getBooleanKeys(const APersistableBundle* _Nonnull pBundle,
                                          char* _Nullable* _Nullable outKeys,
                                          size_t bufferSizeBytes,
                                          APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getIntKeys(const APersistableBundle* _Nonnull pBundle,
                                      char* _Nullable* _Nullable outKeys, size_t bufferSizeBytes,
                                      APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getLongKeys(const APersistableBundle* _Nonnull pBundle,
                                       char* _Nullable* _Nullable outKeys, size_t bufferSizeBytes,
                                       APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getDoubleKeys(const APersistableBundle* _Nonnull pBundle,
                                         char* _Nullable* _Nullable outKeys, size_t bufferSizeBytes,
                                         APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getStringKeys(const APersistableBundle* _Nonnull pBundle,
                                         char* _Nullable* _Nullable outKeys, size_t bufferSizeBytes,
                                         APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getBooleanVectorKeys(const APersistableBundle* _Nonnull pBundle,
                                                char* _Nullable* _Nullable outKeys,
                                                size_t bufferSizeBytes,
                                                APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getIntVectorKeys(const APersistableBundle* _Nonnull pBundle,
                                            char* _Nullable* _Nullable outKeys,
                                            size_t bufferSizeBytes,
                                            APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getLongVectorKeys(const APersistableBundle* _Nonnull pBundle,
                                             char* _Nullable* _Nullable outKeys,
                                             size_t bufferSizeBytes,
                                             APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getDoubleVectorKeys(const APersistableBundle* _Nonnull pBundle,
                                               char* _Nullable* _Nullable outKeys,
                                               size_t bufferSizeBytes,
                                               APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getStringVectorKeys(const APersistableBundle* _Nonnull pBundle,
                                               char* _Nullable* _Nullable outKeys,
                                               size_t bufferSizeBytes,
                                               APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Get all of the keys associated with this specific type and place it in the
 * provided pre-allocated buffer from the user. The user must provide an
 * APersistableBundle_strDupAllocator for the individual strings to be
 * allocated.
 *
 * This function returns the size in bytes required to fit the fill list of keys.
 * The supplied buffer will be filled in based on the smaller of the suplied
 * bufferSizeBytes or the actual size of the stored data.
 * If the buffer is null or if the supplied bufferSizeBytes is smaller than the
 * actual stored data, then not all of the stored data will be returned.
 *
 * Users can call this function with null buffer and 0 bufferSizeBytes to get
 * the required size of the buffer to use on a subsequent call.
 *
 * \return size of the buffer of keys in bytes. This is the required size of the
 * pre-allocated user supplied buffer if all of the stored contents are desired.
 *         0 if no string vector exists for the provided key
 *         -1 if the user supplied APersistableBundle_strDupAllocator returns
 *         false
 */
ssize_t APersistableBundle_getPersistableBundleKeys(
        const APersistableBundle* _Nonnull pBundle, char* _Nullable* _Nullable outKeys,
        size_t bufferSizeBytes, APersistableBundle_strDupAllocator strDupAllocator)
        __INTRODUCED_IN(__ANDROID_API_V__);

__END_DECLS
