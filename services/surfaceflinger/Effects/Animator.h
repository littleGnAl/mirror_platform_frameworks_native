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

#ifndef ANDROID_SURFACE_ANIMATOR_H
#define ANDROID_SURFACE_ANIMATOR_H

#include <stdint.h>
#include <sys/types.h>
#include <utils/RefBase.h>
#include <map>
#include <vector>

namespace android {

enum InterpMode {
    kInterpHold,
    kInterpLinear,
    kInterpSine,   // Sharp start, smooth end
    kInterpCosine, // Smooth start, sharp end
    kInterpSmooth, // Smooth start/end, sharp at the middle
    kInterpSmoothOut = kInterpSine,
    kInterpSmoothIn = kInterpCosine,
};
enum AnimMode {
    kAnimStatic = 0,
    kAnimLoop = 1,
    kAnimOnceStayStart = 2,
    kAnimOnceStayEnd = 3,
    kAnimOnceDestroy = 4,
};

enum AnimParam {
    // Effect 3D Geometry keys
    kAnim3DXAngle = 0,
    kAnim3DYAngle = 1,
    kAnim3DZAngle = 2,
    kAnim3DXPivot = 3,
    kAnim3DYPivot = 4,
    kAnim3DZPivot = 5,
    kAnim3DXTrans = 6,
    kAnim3DYTrans = 7,
    kAnim3DZTrans = 8,
    kAnim3DXScale = 9,
    kAnim3DYScale = 10,
    kAnim3DZScale = 11,
    // Alpha for any effect
    kAnimGenAlpha = 12,
    // Blur effect
    kAnimBlurRadius = 13,
    kAnimBlurAlpha = 15,
    // Region effect
    kAnimRegionSizeX = 20,
    kAnimRegionSizeY = 21,
    kAnimRegionSizeT = 22,
    kAnimRegionPosX = 23,
    kAnimRegionPosY = 24,
    kAnimRegionType = 25,
    kAnimRegionInvert = 26,
    kAnimRegionFactorX = 27,
    kAnimRegionFactorY = 28,
    kAnimRegionFactorCenterX = 29,
    kAnimRegionFactorCenterY = 30,
    kAnimRegionOffsetX = 31,
    kAnimRegionOffsetY = 32,
    // Noise effect
    kAnimNoiseSmoothness = 33,
    kAnimNoisePower = 34,
    kAnimNoiseDynamic = 35,
};

struct AnimKeyframe {
    float value;
    InterpMode imode;
};

class Animator : public LightRefBase<Animator> {
    AnimMode mMode;

    int mNumParams;
    int mCurrFrame;
    int mLastFrame;

    bool mIsRunning;

    std::map<AnimParam, float> mCurrValues;
    std::map<AnimParam, std::map<int, AnimKeyframe> > mKeyframes;

public:
    Animator();
    Animator(AnimMode mode, std::map<AnimParam, float> start_values = std::map<AnimParam, float>());
    virtual ~Animator() {}

    void addKeyframe(AnimParam param, int frame, AnimKeyframe frame_val);
    bool advanceFrame(bool &did_change);
    bool updateParam(AnimParam par);
    static float interpolate(InterpMode mode, float low, float high, float perc);
    float getParam(AnimParam par);
    bool hasParam(AnimParam par) const;

    void restart();

    bool isRunning() const { return mIsRunning; }
};

} // namespace android

#endif // ANDROID_SURFACE_ANIMATOR_H
