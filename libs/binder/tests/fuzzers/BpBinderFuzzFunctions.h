/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef BPBINDER_FUZZER_FUNCTIONS_H_
#define BPBINDER_FUZZER_FUNCTIONS_H_

#include <IBinderFuzzFunctions.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <binder/BpBinder.h>
#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/Stability.h>

#include <cutils/compiler.h>
#include <utils/Log.h>
#include <utils/KeyedVector.h>
#include <utils/Mutex.h>
#include <utils/threads.h>

#include <stdio.h>

namespace android {

// Static variables so we don't consume a bunch of memory to link and
// unlink DeathRecipients.
static int8_t bpbinder_cookie = 0;
static IBinder::DeathRecipient* s_recipient = nullptr;

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, BpBinder*)>> bpBinder_operations =
        {[](FuzzedDataProvider*, BpBinder* bpbinder) -> void { bpbinder->handle(); },
         [](FuzzedDataProvider* fdp, BpBinder* bpbinder) -> void {
             uint32_t flags = fdp->ConsumeIntegral<uint32_t>();

             // Clean up old DeathRecipient to prevent memory leaks or use-after-free issues.
             wp<IBinder::DeathRecipient> out_recipient(nullptr);
             bpbinder->sendObituary();
             bpbinder->unlinkToDeath(nullptr, reinterpret_cast<void*>(&bpbinder_cookie), flags,
                                     &out_recipient);
             s_recipient = new FuzzDeathRecipient();

             bpbinder->linkToDeath(s_recipient, reinterpret_cast<void*>(&bpbinder_cookie), flags);
         },
         [](FuzzedDataProvider* fdp, BpBinder* bpbinder) -> void {
             wp<IBinder::DeathRecipient> out_recipient(nullptr);
             uint32_t flags = fdp->ConsumeIntegral<uint32_t>();
             bpbinder->unlinkToDeath(nullptr, reinterpret_cast<void*>(&bpbinder_cookie), flags,
                                     &out_recipient);
         },
         [](FuzzedDataProvider*, BpBinder* bpbinder) -> void { bpbinder->remoteBinder(); },
         [](FuzzedDataProvider*, BpBinder* bpbinder) -> void { bpbinder->sendObituary(); },
         [](FuzzedDataProvider* fdp, BpBinder* bpbinder) -> void {
             uint32_t uid = fdp->ConsumeIntegral<uint32_t>();
             bpbinder->getBinderProxyCount(uid);
         },
         [](FuzzedDataProvider*, BpBinder* bpbinder) -> void { bpbinder->enableCountByUid(); },
         [](FuzzedDataProvider*, BpBinder* bpbinder) -> void { bpbinder->disableCountByUid(); },
         [](FuzzedDataProvider*, BpBinder* bpbinder) -> void {
             Vector<uint32_t> uids;
             Vector<uint32_t> counts;
             bpbinder->getCountByUid(uids, counts);
         },
         [](FuzzedDataProvider* fdp, BpBinder* bpbinder) -> void {
             bool enable = fdp->ConsumeBool();
             bpbinder->setCountByUidEnabled(enable);
         },
         [](FuzzedDataProvider*, BpBinder* bpbinder) -> void {
             binder_proxy_limit_callback cb = binder_proxy_limit_callback();
             bpbinder->setLimitCallback(cb);
         },
         [](FuzzedDataProvider* fdp, BpBinder* bpbinder) -> void {
             int high = fdp->ConsumeIntegral<int>();
             int low = fdp->ConsumeIntegral<int>();
             bpbinder->setBinderProxyCountWatermarks(high, low);
         }};

} // namespace android
#endif // BPBINDER_FUZZER_FUNCTIONS_H_
