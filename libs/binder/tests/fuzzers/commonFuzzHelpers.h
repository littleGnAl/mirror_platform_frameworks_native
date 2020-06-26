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

#ifndef COMMON_FUZZ_COMMON_HELPERS_H_
#define COMMON_FUZZ_COMMON_HELPERS_H_

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

// Calls a function from the ops_vector
void callArbitraryFunction(FuzzedDataProvider* fdp,
                           std::vector<std::function<void(FuzzedDataProvider*)>> const& ops_vector) {
    // Choose which function we'll be calling
    uint8_t function_id = fdp->ConsumeIntegralInRange<uint8_t>(0, ops_vector.size() - 1);

    // Call the function we've chosen
    ops_vector[function_id](fdp);
}

template <class T>
T getArbitraryVectorElement(FuzzedDataProvider* fdp, std::vector<T> const& vect, bool allow_null) {
    // If we're allowing null, give it a 50:50 shot at returning a nullptr
    if (vect.empty() || (allow_null && fdp->ConsumeBool())) {
        return nullptr;
    }

    // Otherwise, return an element from our vector
    return vect.at(fdp->ConsumeIntegralInRange<size_t>(0, vect.size() - 1));
}

#endif // COMMON_FUZZ_COMMON_HELPERS_H_
