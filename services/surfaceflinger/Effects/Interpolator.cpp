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

#include "Interpolator.h"
#include <cutils/log.h>
#include <math.h>

namespace android {

float LinearInterpolator::interpolate(float value) {
    static float segments[2][3] = {{0.06f, 0.758f, 0.90f}, {0.905f, 0.998f, 1.0f}};
    int length = 2;
    float input = value;
    float loc5 = input;
    int loc6 = length;
    int loc9 = (int)(floor(loc6 * loc5));
    if (loc9 >= length) loc9 = length - 1;
    float loc7 = (loc5 - loc9 * (1.0f / loc6)) * loc6;
    float loc8[3];
    loc8[0] = segments[loc9][0];
    loc8[1] = segments[loc9][1];
    loc8[2] = segments[loc9][2];
    float ret = 0 +
            1 *
                    (loc8[0] +
                     loc7 * (2 * (1 - loc7) * (loc8[1] - loc8[0]) + loc7 * (loc8[2] - loc8[0])));
    return ret;
}

float EaseInInterpolator::interpolate(float /*value*/) {
    // TODO
    return 0.0f;
}

float EaseOutInterpolator::interpolate(float /*value*/) {
    // TODO
    return 0.0f;
}

} // namespace android
