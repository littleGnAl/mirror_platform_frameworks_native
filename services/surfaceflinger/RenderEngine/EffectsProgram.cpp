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

#include "EffectsProgram.h"
#include "EffectsDescription.h"
#include "ProgramCache.h"

#include <math.h>

#include <cutils/log.h>

namespace android {

void EffectsProgram::init(GLuint programId) {
    mTexelOffsetLoc = glGetUniformLocation(programId, "texelOffset");
    mBlurRadiusLoc = glGetUniformLocation(programId, "blurRadius");
    mBlurWeightsLoc = glGetUniformLocation(programId, "blurWeights");
    mMarginsLoc = glGetUniformLocation(programId, "margins");
}

void EffectsProgram::setUniforms(const EffectsDescription& desc) {
    // Blur uniforms
    if (desc.getBlurConfig().isEnabled()) {
        if (CC_LIKELY(mTexelOffsetLoc != -1)) {
            if (mDesc.getBlurConfig().getTexelOffset() != desc.getBlurConfig().getTexelOffset()) {
                glUniform2f(mTexelOffsetLoc, desc.getBlurConfig().getTexelOffset().x,
                            desc.getBlurConfig().getTexelOffset().y);
                mDesc.getBlurConfig().setTexelOffset(desc.getBlurConfig().getTexelOffset());
            }
        }

        if (CC_LIKELY(mBlurRadiusLoc != -1 && mBlurWeightsLoc != -1)) {
            if (mDesc.getBlurConfig().getRadius() != desc.getBlurConfig().getRadius()) {
                glUniform1i(mBlurRadiusLoc, desc.getBlurConfig().getRadius());
                glUniform1fv(mBlurWeightsLoc, desc.getBlurConfig().getRadius() + 1,
                             (GLfloat*)&(desc.getBlurConfig().getWeights()[0]));
                mDesc.getBlurConfig().setRadius(desc.getBlurConfig().getRadius());
            }
        }
        if ((desc.getBlurConfig().isMarginsEnabled()) && CC_LIKELY(mMarginsLoc != -1)) {
            if (mDesc.getBlurConfig().getMargins() != desc.getBlurConfig().getMargins()) {
                const vec4& margins = desc.getBlurConfig().getMargins();
                glUniform4f(mMarginsLoc, margins[0], margins[1], margins[2], margins[3]);
                mDesc.getBlurConfig().setMargins(desc.getBlurConfig().getMargins());
            }
        }
    }
}

} /* namespace android */
