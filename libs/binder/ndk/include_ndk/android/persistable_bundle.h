#ifndef ANDROID_PERSISTABLE_BUNDLE_H
#define ANDROID_PERSISTABLE_BUNDLE_H

#include <android/binder_parcel.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

struct APersistableBundle;
typedef struct APersistableBundle APersistableBundle;

APersistableBundle* _Nullable APersistableBundle_new() __INTRODUCED_IN(35);

APersistableBundle* _Nullable APersistableBundle_dup(const APersistableBundle* _Nonnull pBundle)
        __INTRODUCED_IN(35);
void APersistableBundle_delete(APersistableBundle* _Nonnull pBundle) __INTRODUCED_IN(35);
bool APersistableBundle_isEqual(const APersistableBundle* _Nonnull lhs,
                                const APersistableBundle* _Nonnull rhs) __INTRODUCED_IN(35);
/**
 * Read an APersistableBundle from a AParcel. The output buffer will have an
 * initial reference acquired and will need to be released with
 * AHardwareBuffer_release.
 *
 * Available since API level 35.
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
        __INTRODUCED_IN(35);

/**
 * Write an APersistableBundle to an AParcel.
 *
 * Available since API level 35.
 *
 * \return STATUS_OK on success.
 *         STATUS_BAD_VALUE if either buffer or parcel is null, or if the
 *         APersistableBundle*
 *                          fails to serialize (eg, internally corrupted)
 *         STATUS_NO_MEMORY if the parcel runs out of space to store the buffer & is
 *                          unable to allocate more
 *         STATUS_FDS_NOT_ALLOWED if the parcel does not allow storing FDs
 */
binder_status_t APersistableBundle_writeToParcel(const APersistableBundle* _Nonnull buffer,
                                                 AParcel* _Nonnull parcel) __INTRODUCED_IN(35);

size_t APersistableBundle_size(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
size_t APersistableBundle_erase(APersistableBundle* _Nonnull buffer, const std::string& key)
        __INTRODUCED_IN(35);
void APersistableBundle_putBoolean(APersistableBundle* _Nonnull buffer, const std::string& key,
                                   bool val) __INTRODUCED_IN(35);
void APersistableBundle_putInt(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putLong(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putDouble(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putString(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putBooleanVector(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putIntVector(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putLongVector(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putDoubleVector(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putStringVector(APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_putPersistableBundle(APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getBoolean(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getInt(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getLong(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getDouble(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getString(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getBooleanVector(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getIntVector(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getLongVector(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getDoubleVector(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getStringVector(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getPersistableBundle(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getBooleanKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getIntKeys(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getLongKeys(const APersistableBundle* _Nonnull buffer) __INTRODUCED_IN(35);
void APersistableBundle_getDoubleKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getStringKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getBooleanVectorKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getIntVectorKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getLongVectorKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getDoubleVectorKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getStringVectorKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);
void APersistableBundle_getPersistableBundleKeys(const APersistableBundle* _Nonnull buffer)
        __INTRODUCED_IN(35);

__END_DECLS

#endif  // ANDROID_PERSISTABLE_BUNDLE_H
