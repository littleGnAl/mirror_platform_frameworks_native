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

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <stdint.h>
#include <atomic>

namespace android {

static int8_t bpbinder_cookie = 0;

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, BBinder*)>> bBinder_operations =
        {[](FuzzedDataProvider* fdp, BBinder* bbinder) -> void {
             uint32_t flags = fdp->ConsumeIntegral<uint32_t>();
             bbinder->linkToDeath(nullptr, reinterpret_cast<void*>(&bpbinder_cookie), flags);
         },
         [](FuzzedDataProvider* fdp, BBinder* bbinder) -> void {
             wp<IBinder::DeathRecipient> out_recipient(nullptr);
             uint32_t flags = fdp->ConsumeIntegral<uint32_t>();
             bbinder->unlinkToDeath(nullptr, reinterpret_cast<void*>(&bpbinder_cookie), flags,
                                    &out_recipient);
         },
         [](FuzzedDataProvider*, BBinder* bbinder) -> void { bbinder->localBinder(); },
         [](FuzzedDataProvider*, BBinder* bbinder) -> void { bbinder->isRequestingSid(); },
         [](FuzzedDataProvider* fdp, BBinder* bbinder) -> void {
             bool request_sid = fdp->ConsumeBool();
             bbinder->setRequestingSid(request_sid);
         },
         [](FuzzedDataProvider*, BBinder* bbinder) -> void { bbinder->getExtension(); },
         [](FuzzedDataProvider*, BBinder* bbinder) -> void {
             static IBinder* extension = nullptr;
             bbinder->setExtension(extension);
         },
         [](FuzzedDataProvider*, BBinder* bbinder) -> void { bbinder->getDebugPid(); }};

} // namespace android
#endif // BBINDER_FUZZER_FUNCTIONS_H_
