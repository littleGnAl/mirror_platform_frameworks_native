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

#ifndef SF_RENDER_ENGINE_EFFECTS_DESCRIPTION_H_
#define SF_RENDER_ENGINE_EFFECTS_DESCRIPTION_H_

#include "Effects/BlurEffect.h"
#include "Effects/NoiseEffect.h"
#include "Effects/RegionEffect.h"

namespace android {

/*
 * This holds the state of the rendering engine. This class is used
 * to generate a corresponding GLSL program and set the appropriate
 * uniform.
 *
 * Program and ProgramCache are friends and access the state directly
 */
class EffectsDescription {
public:
    EffectsDescription(){};
    ~EffectsDescription(){};

    const BlurConfig& getBlurConfig() const { return mBlurConfig; }
    const RegionConfig getRegionConfig() const { return mRegionConfig; }
    const NoiseConfig getNoiseConfig() const { return mNoiseConfig; }

    BlurConfig& getBlurConfig() { return mBlurConfig; }
    RegionConfig& getRegionConfig() { return mRegionConfig; }
    NoiseConfig& getNoiseConfig() { return mNoiseConfig; }

private:
    BlurConfig mBlurConfig;
    RegionConfig mRegionConfig;
    NoiseConfig mNoiseConfig;
};

} /* namespace android */

#endif /* SF_RENDER_ENGINE_EFFECTS_DESCRIPTION_H_ */
