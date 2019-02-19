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

#ifndef ANDROID_SURFACE_ANIMATION_INTERPOLATOR_H
#define ANDROID_SURFACE_ANIMATION_INTERPOLATOR_H

#include <stdint.h>
#include <sys/types.h>
#include <utils/RefBase.h>

namespace android {

enum InterpolatorType { INTERPOLATOR_LINEAR, INTERPOLATOR_EASEIN, INTERPOLATOR_EASEOUT };

class Interpolator : public LightRefBase<Interpolator> {
protected:
    Interpolator() {}

public:
    InterpolatorType getType() const { return mType; }
    virtual ~Interpolator() {}
    virtual float interpolate(float value) = 0;

protected:
    InterpolatorType mType;
};

class LinearInterpolator : public Interpolator {
public:
    LinearInterpolator() { mType = INTERPOLATOR_LINEAR; }
    float interpolate(float value);
};

class EaseInInterpolator : public Interpolator {
public:
    EaseInInterpolator() { mType = INTERPOLATOR_EASEIN; }
    float interpolate(float value);
};

class EaseOutInterpolator : public Interpolator {
public:
    EaseOutInterpolator() { mType = INTERPOLATOR_EASEOUT; }
    float interpolate(float value);
};

} // namespace android

#endif // ANDROID_SURFACE_ANIMATION_INTERPOLATOR_H
