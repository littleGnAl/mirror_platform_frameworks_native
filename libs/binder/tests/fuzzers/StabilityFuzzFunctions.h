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

#ifndef STABILITY_FUZZER_FUNCTIONS_H_
#define STABILITY_FUZZER_FUNCTIONS_H_

#include <fuzzer/FuzzedDataProvider.h>
#include <binder/Binder.h>
#include <binder/Stability.h>

#define STABILITY_MAX_TAG_LENGTH 2048

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, android::sp<android::IBinder> const&)>>
        stability_operations = {
                // markCompilationUnit(IBinder* binder)
                [](FuzzedDataProvider*, android::sp<android::IBinder> const& bbinder) -> void {
                    android::internal::Stability::markCompilationUnit(bbinder.get());
                },

                // markVintf(IBinder* binder)
                [](FuzzedDataProvider*, android::sp<android::IBinder> const& bbinder) -> void {
                    android::internal::Stability::markVintf(bbinder.get());
                },

                // debugLogStability(const std::string& tag, const sp<IBinder>& binder)
                [](FuzzedDataProvider* fdp, android::sp<android::IBinder> const& bbinder) -> void {
                    std::string tag = fdp->ConsumeRandomLengthString(STABILITY_MAX_TAG_LENGTH);
                    android::internal::Stability::debugLogStability(tag, bbinder);
                },

                // markVndk(IBinder* binder)
                [](FuzzedDataProvider*, android::sp<android::IBinder> const& bbinder) -> void {
                    android::internal::Stability::markVndk(bbinder.get());
                },

                // requiresVintfDeclaration(const sp<IBinder>& binder)
                [](FuzzedDataProvider*, android::sp<android::IBinder> const& bbinder) -> void {
                    android::internal::Stability::requiresVintfDeclaration(bbinder);
                }};

#endif // STABILITY_FUZZER_FUNCTIONS_H_
