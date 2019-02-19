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

#ifndef ANDROID_TRANSFORM_UTILS_H
#define ANDROID_TRANSFORM_UTILS_H

#include <Transform.h>
#include <math/mat4.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ui/Point.h>
#include <ui/Rect.h>

namespace android {

class RenderEngine;
class EffectsRenderEngine;

class TransformUtils {
public:
    static constexpr float PI = 3.14159265f;
    static constexpr float FOV = 30.0f;
    static mat4 rotate(const mat4& matrix, float a, float x, float y, float z);
    static mat4 translate(const mat4& matrix, float tx, float ty, float tz);
    static mat4 preMultiply(const mat4& lhs, const mat4& rhs);
    static mat4 loadIdentity();

    static Transform::orientation_flags hwRotationToTransformFlags(int orientation);
    static Transform::orientation_flags hwRotationToTransformFlagsInv(int orientation);
};

} // namespace android
#endif /* ANDROID_TRANSFORM_UTILS_H */
