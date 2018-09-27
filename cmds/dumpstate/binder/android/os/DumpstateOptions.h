#ifndef ANDROID_OS_DUMPSTATE_OPTIONS_H_
#define ANDROID_OS_DUMPSTATE_OPTIONS_H_

#include <binder/BinderService.h>

namespace android {
namespace os {

struct DumpstateOptions : public android::Parcelable {
    // If true the caller can get callbacks with per-section progress details.
    bool get_section_details;

    // Name of the caller.
    std::string name;

    status_t writeToParcel(android::Parcel* parcel) const override;
    status_t readFromParcel(const android::Parcel* parcel) override;
};

}  // namespace os
}  // namespace android

#endif  // ANDROID_OS_DUMPSTATE_OPTIONS_H_
