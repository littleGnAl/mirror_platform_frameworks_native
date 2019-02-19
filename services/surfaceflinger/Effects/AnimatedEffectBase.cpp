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

#include "AnimatedEffectBase.h"

namespace android {

AnimatedEffectBase::AnimatedEffectBase() : mUpdated(false) {}

void AnimatedEffectBase::setAnimator(sp<Animator>& anim) {
    mAnimator = anim;
    mUpdated = true;
}

sp<Animator> AnimatedEffectBase::getAnimator() const {
    return mAnimator;
}

bool AnimatedEffectBase::advanceAnimation(bool& outChanged) {
    return mAnimator != nullptr && mAnimator->advanceFrame(outChanged);
}

bool AnimatedEffectBase::isAnimationRunning() const {
    return mAnimator != nullptr && mAnimator->isRunning();
}

bool AnimatedEffectBase::isUpdated() const {
    return mUpdated;
}

void AnimatedEffectBase::resetUpdatedFlag() {
    mUpdated = false;
}

} // namespace android
