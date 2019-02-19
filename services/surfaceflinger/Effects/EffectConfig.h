/*
 * Copyright (C) 2019 Samsung Electronics
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

#ifndef ANDROID_EFFECT_CONFIG_H
#define ANDROID_EFFECT_CONFIG_H

#include "Effect.h"

namespace android {

class EffectConfig {
protected:
    bool mEnabled;
    // All the configs should define the == operator, for checkin if the config has changed
public:
    EffectConfig() { mEnabled = false; }

    bool isEnabled() const { return mEnabled; }
};

}; // namespace android

#endif // ANDROID_EFFECT_CONFIG_H
