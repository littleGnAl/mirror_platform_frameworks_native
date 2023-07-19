/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <fuzzbinder/libbinder_driver.h>

#include <fuzzbinder/random_parcel.h>

#include <android-base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>

#include <private/android_filesystem_config.h>
namespace android {

void fuzzService(const sp<IBinder>& binder, FuzzedDataProvider&& provider) {
    fuzzService(std::vector<sp<IBinder>>{binder}, std::move(provider));
}

void fuzzService(const std::vector<sp<IBinder>>& binders, FuzzedDataProvider&& provider) {

    // Reserved bytes so that we don't have to change fuzzers and seed corpus if
    // we introduce anything new in fuzzService.
    std::vector<uint8_t> reservedBytes =  provider.ConsumeBytes<uint8_t>(8);
    (void)reservedBytes;

    RandomParcelOptions options{
            .extraBinders = binders,
            .extraFds = {},
    };

    // always refresh the calling identity, because we sometimes set it below, but also,
    // the code we're fuzzing might reset it
    IPCThreadState::self()->clearCallingIdentity();

    // Always take so that a perturbation of just the one ConsumeBool byte will always
    // take the same path, but with a different UID. Without this, the fuzzer needs to
    // guess both the change in value and the shift at the same time.
    int64_t thirdUid = provider.ConsumeIntegralInRange<int64_t>(static_cast<int64_t>(AID_ROOT) << 32,
                                             static_cast<int64_t>(AID_USER) << 32);
    int64_t fourthUid = provider.ConsumeIntegral<int64_t>();
    int64_t maybeSetUid = provider.PickValueInArray<int64_t>(
            {static_cast<int64_t>(AID_ROOT) << 32, static_cast<int64_t>(AID_SYSTEM) << 32, thirdUid,
             fourthUid});
    std::cout << "maybeSetUid read : " << maybeSetUid << std::endl;
    if (provider.ConsumeBool()) {
        // set calling uid
        LOG_ALWAYS_FATAL("unintended path in corpusasdasdas");
        IPCThreadState::self()->restoreCallingIdentity(maybeSetUid);
    }

    while (provider.remaining_bytes() > 0) {
        // Most of the AIDL services will have small set of transaction codes.
        uint32_t code = provider.ConsumeBool() ? provider.ConsumeIntegral<uint32_t>()
                                               : provider.ConsumeIntegralInRange<uint32_t>(0, 100);
        std::cout << "Code read : " << code << std::endl;
        uint32_t flags = provider.ConsumeIntegral<uint32_t>();
        std::cout << "flags read : " << flags << std::endl;
        Parcel data;
        // for increased fuzz coverage
        data.setEnforceNoDataAvail(false);
        data.setServiceFuzzing();

        size_t extraBindersIndex  =  provider.ConsumeIntegralInRange<size_t>(0, options.extraBinders.size() - 1);
        sp<IBinder> target = options.extraBinders.at(extraBindersIndex);
        std::cout << "extraBindersIndex read : " << extraBindersIndex << std::endl;

        options.writeHeader = [&target](Parcel* p, FuzzedDataProvider& provider) {
            // most code will be behind checks that the head of the Parcel
            // is exactly this, so make it easier for fuzzers to reach this
            if (provider.ConsumeBool()) {
                std::cout << "Write interface token "<< std::endl;
                p->writeInterfaceToken(target->getInterfaceDescriptor());
            }
        };

        size_t subDataSize = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
        std::cout << "subDataSize read : " << subDataSize << std::endl;
        std::vector<uint8_t> subData = provider.ConsumeBytes<uint8_t>(subDataSize);
        fillRandomParcel(&data, FuzzedDataProvider(subData.data(), subData.size()), &options);

        Parcel reply;
        // for increased fuzz coverage
        reply.setEnforceNoDataAvail(false);
        reply.setServiceFuzzing();
        (void)target->transact(code, data, &reply, flags);

        // feed back in binders and fds that are returned from the service, so that
        // we can fuzz those binders, and use the fds and binders to feed back into
        // the binders
        auto retBinders = reply.debugReadAllStrongBinders();
        options.extraBinders.insert(options.extraBinders.end(), retBinders.begin(),
                                    retBinders.end());
        auto retFds = reply.debugReadAllFileDescriptors();
        for (size_t i = 0; i < retFds.size(); i++) {
            options.extraFds.push_back(base::unique_fd(dup(retFds[i])));
        }
    }

    // invariants
    auto ps = ProcessState::selfOrNull();
    if (ps) {
        CHECK_EQ(0, ps->getThreadPoolMaxTotalThreadCount())
                << "Binder threadpool should not be started by fuzzer because coverage can only "
                   "cover in-process calls.";
    }
}

} // namespace android
