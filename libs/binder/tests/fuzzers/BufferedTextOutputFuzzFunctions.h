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

#pragma once

#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include "BufferedTextOutput.h"

namespace android {

static size_t kPushCount = 0;

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<
        std::function<void(FuzzedDataProvider*, const std::shared_ptr<BufferedTextOutput>&)>>
        gBufferedTextOutputOperations =
                {[](FuzzedDataProvider*,
                    const std::shared_ptr<BufferedTextOutput>& b_text_output) -> void {
                     b_text_output->pushBundle();
                     kPushCount++;
                 },
                 [](FuzzedDataProvider* fdp,
                    const std::shared_ptr<BufferedTextOutput>& b_text_output) -> void {
                     std::string txt = fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
                     size_t len = fdp->ConsumeIntegralInRange<size_t>(0, txt.length());
                     b_text_output->print(txt.c_str(), len);
                 },
                 [](FuzzedDataProvider*,
                    const std::shared_ptr<BufferedTextOutput>& b_text_output) -> void {
                     if (kPushCount == 0) return;

                     b_text_output->popBundle();
                     kPushCount--;
                 }};

} // namespace android
