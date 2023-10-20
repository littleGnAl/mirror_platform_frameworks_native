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

__END_DECLS

#endif  // ANDROID_PERSISTABLE_BUNDLE_H
