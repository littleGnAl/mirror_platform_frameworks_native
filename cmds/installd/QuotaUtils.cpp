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

namespace android {
namespace installd {

bool QuotaUtils::invalidateMounts() {
	std::lock_guard<std::recursive_mutex> lock(mMountsLock);

	mQuotaReverseMounts.clear();

    std::ifstream in("/proc/mounts");
    if (!in.is_open()) {
        return false;
    }

    std::string source;
    std::string target;
    std::string ignored;
    while (!in.eof()) {
        std::getline(in, source, ' ');
        std::getline(in, target, ' ');
        std::getline(in, ignored);

        if (source.compare(0, 11, "/dev/block/") == 0) {
            struct dqblk dq;
            if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), source.c_str(), 0,
                    reinterpret_cast<char*>(&dq)) == 0) {
                LOG(DEBUG) << "Found quota mount " << source << " at " << target;
                mQuotaReverseMounts[target] = source;
            }
        }
	}
	return true;
}

bool QuotaUtils::isQuotaSupported(const std::unique_ptr<std::string>& uuid) {
    return !findQuotaDeviceForUuid(uuid).empty();
}

int64_t getOccupiedSpaceForUid(const std::unique_ptr<std::string>& uuid, uid_t uid) {
    const std::string device = findQuotaDeviceForUuid(uuid);
    if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), device.c_str(), uid,
            reinterpret_cast<char*>(&dq)) != 0) {
        if (errno != ESRCH) {
            PLOG(ERROR) << "Failed to quotactl " << device << " for UID " << uid;
        }
		return -1;
    } else {
#if MEASURE_DEBUG
        LOG(DEBUG) << "quotactl() for UID " << uid << " " << dq.dqb_curspace;
#endif
        return dq.dqb_curspace;
    }
}

int64_t getOccupiedSpaceForGid(const std::unique_ptr<std::string>& uuid, gid_t gid) {
    const std::string device = findQuotaDeviceForUuid(uuid);
    if (quotactl(QCMD(Q_GETQUOTA, GRPQUOTA), device.c_str(), gid,
            reinterpret_cast<char*>(&dq)) != 0) {
        if (errno != ESRCH) {
            PLOG(ERROR) << "Failed to quotactl " << device << " for GID " << gid;
        }
		return -1;
    } else {
#if MEASURE_DEBUG
        LOG(DEBUG) << "quotactl() for GID " << gid << " " << dq.dqb_curspace;
#endif
        return dq.dqb_curspace;
    }

}


std::string QuotaUtils::findQuotaDeviceForUuid(
        const std::unique_ptr<std::string>& uuid) {
    std::lock_guard<std::recursive_mutex> lock(mMountsLock);
    auto path = create_data_path(uuid ? uuid->c_str() : nullptr);
    return mQuotaReverseMounts[path];
}

}  // namespace installd
}  // namespace android
