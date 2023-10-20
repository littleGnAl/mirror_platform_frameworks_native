#include <android/binder_libbinder.h>
#include <android/persistable_bundle.h>
#include <binder/PersistableBundle.h>
#include <log/log.h>

namespace android {

struct APersistableBundle {
    os::PersistableBundle mPBundle;
};

APersistableBundle* APersistableBundle_new() {
    return new APersistableBundle();
}

binder_status_t APersistableBundle_readFromParcel(
        const AParcel* _Nonnull parcel, APersistableBundle* _Nullable* _Nonnull outPBundle) {
    if (!parcel || !outPBundle) return STATUS_BAD_VALUE;
    binder_status_t status =
            newPBundle->mPBundle.readFromParcel(AParcel_viewPlatformParcel(parcel));
    if (status == STATUS_OK) {
        *outPBundle = newPBundle;
    }
    return status;
}

binder_status_t APersistableBundle_writeToParcel(const APersistableBundle* _Nonnull pBundle,
                                                 AParcel* _Nonnull parcel) {
    if (!parcel || !pBundle) return STATUS_BAD_VALUE;
    return pBundle->mPBundle.writeToParcel(AParcel_viewPlatformParcel(parcel));
}

}  // namespace android
