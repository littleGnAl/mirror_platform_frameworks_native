/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef ANDROID_AIDL_AIDLSUPPORT_H
#define ANDROID_AIDL_AIDLSUPPORT_H

namespace android {
namespace details {
// Never instantiated. Used as a placeholder for template variables.
template <typename T>
struct aidl_invalid_type;
}  // namespace detail

// AIDL generates specializations of this for enums.
// Usage: for (const auto v : aidl_enum_values<Enum>) { ... }
template <typename EnumType>
constexpr details::aidl_invalid_type<EnumType> aidl_enum_values;

}  // namespace android

#endif // ANDROID_AIDL_AIDLSUPPORT_H