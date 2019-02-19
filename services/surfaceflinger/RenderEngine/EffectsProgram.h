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

#ifndef SF_RENDER_ENGINE_EFFECTS_PROGRAM_H
#define SF_RENDER_ENGINE_EFFECTS_PROGRAM_H

#include <GLES2/gl2.h>
#include "EffectsDescription.h"

namespace android {

class EffectsDescription;

/*
 * Abstracts a GLSL program comprising a vertex and fragment shader
 */
class EffectsProgram {
public:
    EffectsProgram() {}

    void init(GLuint programId);
    ~EffectsProgram();

    /* set-up uniforms from the description */
    void setUniforms(const EffectsDescription& desc);

private:
    /*Effects uniforms*/
    // Blur
    GLint mTexelOffsetLoc;
    GLint mBlurRadiusLoc;
    GLint mBlurWeightsLoc;
    GLint mMarginsLoc;

    // Current description state, holding the current uniforms set for this shader
    EffectsDescription mDesc;
};

} /* namespace android */

#endif /* SF_RENDER_ENGINE_EFFECTS_PROGRAM_H */
