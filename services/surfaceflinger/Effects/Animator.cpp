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

#include <cutils/log.h>

#include <math.h> /* sin */
#include "Animator.h"

namespace android {

Animator::Animator() {
    mMode = kAnimStatic;
    mNumParams = 0;
    mCurrFrame = 0;
    mLastFrame = 0;
    mIsRunning = false;
}
Animator::Animator(AnimMode mode, std::map<AnimParam, float> start_values) {
    mMode = mode;
    mIsRunning = mode != kAnimStatic;
    mCurrFrame = 0;
    mLastFrame = 0;
    mNumParams = 0;
    mCurrValues = start_values;
    // Set the keyframes 0 as the start values (can be overwriten later on, since they are in a map)
    for (std::map<AnimParam, float>::iterator it = start_values.begin(); it != start_values.end();
         it++) {
        mKeyframes[it->first][0].value = it->second;
        mKeyframes[it->first][0].imode = kInterpHold;
    }
}

void Animator::restart() {
    mIsRunning = true;
    mCurrFrame = 0;
    // Reset to the start parameters
    for (std::map<AnimParam, std::map<int, AnimKeyframe> >::iterator it = mKeyframes.begin();
         it != mKeyframes.end(); it++) {
        mCurrValues[it->first] = it->second[0].value;
    }
}

void Animator::addKeyframe(AnimParam par, int frame, AnimKeyframe frame_val) {
    // Does the param exits? If not use this value as start value
    if (!hasParam(par)) {
        mKeyframes[par][0].value = frame_val.value;
        mKeyframes[par][0].imode = kInterpHold;
    }
    // Add the keyframe
    mKeyframes[par][frame] = frame_val;
    if (frame > mLastFrame) // Check and increase the total animation duration
        mLastFrame = frame;
    updateParam(par);
}

bool Animator::advanceFrame(bool& did_change) {
    if (!mIsRunning) return false;
    if (mMode == kAnimStatic ||
        (0 == mLastFrame && mMode == kAnimLoop)) { // Avoid loop animation without changes
        mIsRunning = false;
        return false; // Nothing to do
    }
    if (mCurrFrame >= mLastFrame) {
        if (mMode == kAnimOnceDestroy) return true; // Signals a destruction
        if (mMode == kAnimLoop) {
            mCurrFrame = 0;
        } else {
            if (mMode == kAnimOnceStayStart) {
                restart();
            }
            mIsRunning = false; // Stop the animation
            return false;
        }
    }
    // Advance every param to the next frame
    mCurrFrame++;
    for (std::map<AnimParam, std::map<int, AnimKeyframe> >::iterator it = mKeyframes.begin();
         it != mKeyframes.end(); it++) {
        did_change |= updateParam(it->first);
    }
    return false;
}

bool Animator::updateParam(AnimParam par) {
    // Get the closer keyframes of this parameter
    int low = -1;
    int high = -1;
    for (std::map<int, AnimKeyframe>::iterator it = mKeyframes[par].begin();
         it != mKeyframes[par].end(); ++it) {
        if (it->first <= mCurrFrame) {
            low = it->first;
        }
        if (it->first >= mCurrFrame) {
            high = it->first;
            break;
        }
    }
    float o_val = mCurrValues[par];
    if (low == high || high == -1) {
        mCurrValues[par] = mKeyframes[par][low].value;
    } else {
        mCurrValues[par] =
                interpolate(mKeyframes[par][high].imode, mKeyframes[par][low].value,
                            mKeyframes[par][high].value, ((float)mCurrFrame - low) / (high - low));
    }
    if (o_val != mCurrValues[par]) return true; // Parameter updated
    return false;                               // Nothing updated
}

float Animator::interpolate(InterpMode mode, float low, float high, float perc) {
    float d = high - low;
    switch (mode) {
        case kInterpLinear:
            return low + d * perc;
        case kInterpSine:
            return low + d * sin(perc * M_PI_2);
        case kInterpCosine:
            return low + d * (1 - cos(perc * M_PI_2));
        case kInterpSmooth:
            return low + d * (1 + sin(perc * M_PI - M_PI_2)) / 2.0f;
        case kInterpHold:
        default:
            return low;
    };
    return 0;
}

bool Animator::hasParam(AnimParam par) const {
    return mKeyframes.count(par) > 0;
}

float Animator::getParam(AnimParam par) {
    if (!hasParam(par)) return 0; // Param does not exist return 0
    return mCurrValues[par];
}

} // namespace android
