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

#include "TransformUtils.h"

#include <cutils/compiler.h>
#include <cutils/log.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <ui/Region.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include "Layer.h"

#define DEBUG_USE_FLOATS 0

namespace android {

static const float EPSILON = 0.0f;

static float sinef(float x) {
    const float A = 1.0f / (2.0f * M_PI);
    const float B = -16.0f;
    const float C = 8.0f;

    // scale angle for easy argument reduction
    x *= A;

    if (fabsf(x) >= 0.5f) {
        // Argument reduction
        x = x - ceilf(x + 0.5f) + 1.0f;
    }

    const float y = B * x * fabsf(x) + C * x;
    return 0.2215f * (y * fabsf(y) - y) + y;
}

static float cosinef(float x) {
    return sinef(x + float(M_PI / 2));
}

static void sincosf(float angle, float* s, float* c) {
    *s = sinef(angle);
    *c = cosinef(angle);
}

static bool isZero(float f) {
    return fabs(f) <= EPSILON;
}

static bool isOne(float f) {
    return isZero(f - 1.0f);
}

static float reciprocal(float v) {
    return 1.0f / v;
}

mat4 TransformUtils::rotate(const mat4& matrix, float a, float x, float y, float z) {
    mat4 rotation;
    // float* r = rotation.asArray();
    float c, s;
    rotation[0][3] = 0;
    rotation[1][3] = 0;
    rotation[2][3] = 0;
    rotation[3][0] = 0;
    rotation[3][1] = 0;
    rotation[3][2] = 0;
    rotation[3][3] = 1;
    a *= float(M_PI / 180.0f);
    sincosf(a, &s, &c);
    if (isOne(x) && isZero(y) && isZero(z)) {
        rotation[0][0] = 1;
        rotation[1][0] = 0;
        rotation[2][0] = 0;
        rotation[0][1] = 0;
        rotation[1][1] = c;
        rotation[2][1] = -s;
        rotation[0][2] = 0;
        rotation[1][2] = s;
        rotation[2][2] = c;
    } else if (isZero(x) && isOne(y) && isZero(z)) {
        rotation[0][0] = c;
        rotation[1][0] = 0;
        rotation[2][0] = s;
        rotation[0][1] = 0;
        rotation[1][1] = 1;
        rotation[2][1] = 0;
        rotation[0][2] = -s;
        rotation[1][2] = 0;
        rotation[2][2] = c;
    } else if (isZero(x) && isZero(y) && isOne(z)) {
        rotation[0][0] = c;
        rotation[1][0] = -s;
        rotation[2][0] = 0;
        rotation[0][1] = s;
        rotation[1][1] = c;
        rotation[2][1] = 0;
        rotation[0][2] = 0;
        rotation[1][2] = 0;
        rotation[2][2] = 1;
    } else if (isZero(x) && isZero(y) && isZero(z)) {
        rotation[0][0] = 1;
        rotation[1][0] = 0;
        rotation[2][0] = 0;
        rotation[0][1] = 0;
        rotation[1][1] = 1;
        rotation[2][1] = 0;
        rotation[0][2] = 0;
        rotation[1][2] = 0;
        rotation[2][2] = 1;
    } else {
        const float len = sqrtf(x * x + y * y + z * z);
        if (!isOne(len)) {
            const float recipLen = reciprocal(len);
            x *= recipLen;
            y *= recipLen;
            z *= recipLen;
        }
        const float nc = 1.0f - c;
        const float xy = x * y;
        const float yz = y * z;
        const float zx = z * x;
        const float xs = x * s;
        const float ys = y * s;
        const float zs = z * s;
        rotation[0][0] = x * x * nc + c;
        rotation[1][0] = xy * nc - zs;
        rotation[2][0] = zx * nc + ys;
        rotation[0][1] = xy * nc + zs;
        rotation[1][1] = y * y * nc + c;
        rotation[2][1] = yz * nc - xs;
        rotation[0][2] = zx * nc - ys;
        rotation[1][2] = yz * nc + xs;
        rotation[2][2] = z * z * nc + c;
    }

    return preMultiply(rotation, matrix);
}

mat4 TransformUtils::translate(const mat4& matrix, float tx, float ty, float tz) {
    mat4 translation;
    translation[0][0] = translation[1][1] = translation[2][2] = translation[3][3] = 1;
    translation[0][1] = translation[0][2] = 0;
    translation[1][0] = translation[1][2] = 0;
    translation[2][0] = translation[2][1] = 0;
    translation[3][0] = translation[3][1] = translation[3][2] = 0;
    translation[3][0] = tx;
    translation[3][1] = ty;
    translation[3][2] = tz;

    return preMultiply(translation, matrix);
}

mat4 TransformUtils::preMultiply(const mat4& lhs, const mat4& rhs) {
    // Pre-Multiplies the incoming Matrix with the existing Matrix
    mat4 result;
    float sum = 0;
    for (int c = 0; c < 4; c++) {
        for (int d = 0; d < 4; d++) {
            for (int k = 0; k < 4; k++) {
                sum = sum + lhs[c][k] * rhs[k][d];
            }
            result[c][d] = sum;
            sum = 0;
        }
    }
    return result;
}

mat4 TransformUtils::loadIdentity() {
    // sets the ModelView Matrix to Identity
    mat4 result = mat4(0);
    for (int i = 0; i < 4; i++) {
        result[i][i] = 1;
    }
    return result;
}

Transform::orientation_flags TransformUtils::hwRotationToTransformFlags(int orientation) {
    Transform::orientation_flags transform = Transform::ROT_0;
    switch (orientation) {
        case DisplayState::eOrientationDefault:
            transform = Transform::ROT_0;
            break;
        case DisplayState::eOrientation90:
            transform = Transform::ROT_90;
            break;
        case DisplayState::eOrientation180:
            transform = Transform::ROT_180;
            break;
        case DisplayState::eOrientation270:
            transform = Transform::ROT_270;
            break;
    }
    return transform;
}

Transform::orientation_flags TransformUtils::hwRotationToTransformFlagsInv(int orientation) {
    Transform::orientation_flags transform = Transform::ROT_0;
    switch (orientation) {
        case DisplayState::eOrientationDefault:
            transform = Transform::ROT_0;
            break;
        case DisplayState::eOrientation90:
            transform = Transform::ROT_270;
            break;
        case DisplayState::eOrientation180:
            transform = Transform::ROT_180;
            break;
        case DisplayState::eOrientation270:
            transform = Transform::ROT_90;
            break;
    }
    return transform;
}

} // namespace android
