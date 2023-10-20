
#ifndef ANDROID_PERSISTABLE_BUNDLE_AIDL_H
#define ANDROID_PERSISTABLE_BUNDLE_AIDL_H

#include <android/binder_parcel.h>
#include <android/persistable_bundle.h>
#include <sys/cdefs.h>

#ifdef __cplusplus
#include <string>
#endif

// Only enable the AIDL glue helper if this is C++
#ifdef __cplusplus

namespace aidl::android {

/**
 * Wrapper class that enables interop with AIDL NDK generation
 * Takes ownership of the APersistableBundle* given to it in reset() and will automatically
 * destroy it in the destructor, similar to a smart pointer container
 */
class PersistableBundle {
public:
    PersistableBundle() noexcept {}
    PersistableBundle(PersistableBundle&& other) noexcept : mPBundle(other.release()) {}

    ~PersistableBundle() {
        reset();
    }

    binder_status_t readFromParcel(const AParcel* _Nonnull parcel) {
        reset();
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_readFromParcel(parcel, &mPBundle);
        } else {
            return STATUS_FAILED_TRANSACTION;
        }
    }

    binder_status_t writeToParcel(AParcel* _Nonnull parcel) const {
        if (!mPBundle) {
            return STATUS_BAD_VALUE;
        }
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return APersistableBundle_writeToParcel(mPBundle, parcel);
        } else {
            return STATUS_FAILED_TRANSACTION;
        }
    }

    /**
     * Destroys any currently owned APersistableBundle* and takes ownership of the given
     * APersistableBundle*
     *
     * @param buffer The buffer to take ownership of
     */
    void reset(APersistableBundle* _Nullable buffer = nullptr) noexcept {
        if (mPBundle) {
            APersistableBundle_release(mPBundle);
            mPBundle = nullptr;
        }
        mPBundle = buffer;
    }

    inline APersistableBundle* _Nullable operator-> () const { return mPBundle;  }
    inline APersistableBundle* _Nullable get() const { return mPBundle; }
    inline explicit operator bool () const { return mPBundle != nullptr; }

    inline bool operator!=(const PersistableBundle& rhs) const { return get() != rhs.get(); }
    inline bool operator<(const PersistableBundle& rhs) const { return get() < rhs.get(); }
    inline bool operator<=(const PersistableBundle& rhs) const { return get() <= rhs.get(); }
    inline bool operator==(const PersistableBundle& rhs) const { return get() == rhs.get(); }
    inline bool operator>(const PersistableBundle& rhs) const { return get() > rhs.get(); }
    inline bool operator>=(const PersistableBundle& rhs) const { return get() >= rhs.get(); }

    PersistableBundle& operator=(PersistableBundle&& other) noexcept {
        reset(other.release());
        return *this;
    }

    /**
     * Stops managing any contained APersistableBundle*, returning it to the caller. Ownership
     * is released.
     * @return APersistableBundle* or null if this was empty
     */
    [[nodiscard]] APersistableBundle* _Nullable release() noexcept {
        APersistableBundle* _Nullable ret = mPBundle;
        mPBundle = nullptr;
        return ret;
    }

    inline std::string toString() const {
        if (!mPBundle) {
            return "<PersistableBundle: Invalid>";
        }
        if (__builtin_available(android __ANDROID_API_V__, *)) {
            return "<PersistableBundle " + "TODO" + ">";
        } else {
            return "<PersistableBundle (unknown)>";
        }
    }

private:
    PersistableBundle(const PersistableBundle& other) = delete;
    PersistableBundle& operator=(const PersistableBundle& other) = delete;

    APersistableBundle* _Nullable mPBundle = nullptr;
};

} // aidl::android

#endif // __cplusplus

#endif // ANDROID_PERSISTABLE_BUNDLE_AIDL_H
