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

#pragma once

#include <input/Input.h>
#include <android/keycodes.h>
#include <unordered_map>

namespace android {

template<typename T, size_t N>
size_t size(T (&)[N]) { return N; }

struct InputEventLabel {
    const char *literal;
    int value;
};

struct EvdevEventLabel {
    std::string type;
    std::string code;
    std::string value;
};

//   NOTE: If you want a new key code, axis code, led code or flag code in keylayout file,
//   then you must add it to InputEventLabels.cpp.

class InputEventLookup {
public:
    static std::optional<int> lookupValueByLabel(const std::unordered_map<std::string, int>& map,
                                                 const char* literal);

    static const char* lookupLabelByValue(const std::vector<InputEventLabel>& vec, int value);

    static std::optional<int> getKeyCodeByLabel(const char* label);

    static const char* getLabelByKeyCode(int32_t keyCode);

    static std::optional<int> getKeyFlagByLabel(const char* label);

    static std::optional<int> getAxisByLabel(const char* label);

    static const char* getAxisLabel(int32_t axisId);

    static std::optional<int> getLedByLabel(const char* label);

    static EvdevEventLabel getLinuxEvdevLabel(int32_t type, int32_t code, int32_t value);

private:
    static const std::unordered_map<std::string, int> KEYCODES;

    static const std::vector<InputEventLabel> KEY_NAMES;

    static const std::unordered_map<std::string, int> AXES;

    static const std::vector<InputEventLabel> AXES_NAMES;

    static const std::unordered_map<std::string, int> LEDS;

    static const std::unordered_map<std::string, int> FLAGS;
};

} // namespace android
