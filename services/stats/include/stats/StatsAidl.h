/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <aidl/android/frameworks/stats/BnStats.h>

namespace aidl {
namespace android {
namespace frameworks {
namespace stats {

class StatsHal : public BnStats {
public:
    StatsHal();

    /**
     * Binder call to get vendor atom.
     */
    virtual ndk::ScopedAStatus reportVendorAtom(
        const VendorAtom& in_vendorAtom) override;

    virtual ndk::ScopedAStatus reportVendorAtomSync(
        const VendorAtom& in_vendorAtom) override {
        return reportVendorAtom(in_vendorAtom);
    }
};

}  // namespace stats
}  // namespace frameworks
}  // namespace android
}  // namespace aidl
