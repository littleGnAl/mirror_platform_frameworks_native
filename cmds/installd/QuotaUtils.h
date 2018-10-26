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

#ifndef ANDROID_INSTALLD_QUOTA_UTILS_H_
#define ANDROID_INSTALLD_QUOTA_UTILS_H_


namespace android {
namespace installd {

class QuotaUtils {
  public:
    /* Clear and recompute the reverse mounts map */
    bool invalidateMounts();

    /* Whether quota is supported in the device with the given uuid */
    bool isQuotaSupported(const std::unique_ptr<std::string>& uuid);

    /* Get the current occupied space in bytes for a uid or -1 if fails */
    int64_t getOccupiedSpaceForUid(const std::unique_ptr<std::string>& uuid, uid_t uid);

    /* Get the current occupied space in bytes for a gid or -1 if fails */
    int64_t getOccupiedSpaceForGid(const std::unique_ptr<std::string>& uuid, gid_t gid);

  private:
    std::string findQuotaDeviceForUuid(const st::unique_ptr<std::string>& uuid);

    std::recursive_mutex mMountsLock;

    /* Map of all quota mounts from target to source */
    std::unordered_map<std::string, std::string> mQuotaReverseMounts;
}

}  // namespace installd
}  // namespace android

#endif  // ANDROID_INSTALLD_QUOTA_UTILS_H
