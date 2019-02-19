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

#include "ProgramCache.h"
#include "Description.h"
#include <cutils/log.h>
#include "Formatter.h"

namespace android {

void ProgramCache::computeEffectsKey(ProgramCache::Key& needs, const Description& description) {

    needs.set(ProgramCache::Key::EFFECT_BLUR_MASK,
              !description.getEffectDesc().getBlurConfig().isEnabled() ? ProgramCache::Key::EFFECT_BLUR_OFF :
              description.getEffectDesc().getNoiseConfig().isEnabled() ? ProgramCache::Key::EFFECT_BLUR_NOISE_ON : ProgramCache::Key::EFFECT_BLUR_ON )
            .set(ProgramCache::Key::EFFECT_BLUR_MARGINS_MASK,
                 description.getEffectDesc().getBlurConfig().isMarginsEnabled() ? ProgramCache::Key::EFFECT_BLUR_MARGINS_ON : ProgramCache::Key::EFFECT_BLUR_MARGINS_OFF);
}

Formatter& ProgramCache::initEffectsFragmentShader(const ProgramCache::Key& needs, Formatter& fs) {
    if (isBlurEnabled(needs)) {
        fs  <<  "uniform vec2 texelOffset;";
        fs  <<  "uniform float blurWeights[16];";
        fs  <<  "uniform int blurRadius;";
        fs  <<  "uniform vec4 margins;";
    }
    if (isNoiseEnabled(needs)) {
        fs << "uniform vec3 noiseParams;";
    }
    if (isRegionEnabled(needs)) {
        fs << "uniform vec2 regPos;";
        fs << "uniform vec2 regSize;";
        fs << "uniform vec2 regFactor;";
        fs << "uniform float regTsize;";
        fs << "uniform bool  reginvert;";
        fs << "uniform int  regtype;";
    }
    return fs;
}

Formatter& ProgramCache::generateEffectsFragmentShader(const ProgramCache::Key& needs, Formatter& fs) {

    if (isBlurEnabled(needs)) {
        fs << "highp vec4 sum = vec4(0.0);";

        if (isBlurMarginsEnabled(needs)) {
            fs  << "vec2 tmin = margins.rb;"
                << "vec2 tmax = margins.ga;";
            fs  << "#define CLAMP(a) clamp((a), tmin, tmax)";
        } else {
            fs  << "#define CLAMP(a) (a)";
        }

        fs << "sum += texture2D(sampler, CLAMP(outTexCoords)) * blurWeights[0];";
        fs << "for(int i = 1; i < blurRadius+1; i++) {";
        fs << "   sum += texture2D(sampler, CLAMP(outTexCoords + (texelOffset * float(i)))) * blurWeights[i];";
        fs << "   sum += texture2D(sampler, CLAMP(outTexCoords - (texelOffset * float(i)))) * blurWeights[i];";
        fs << "}";
        fs << "gl_FragColor = sum;";
    } else if (isNoiseEnabled(needs)) {
        fs << "vec4 pixel = texture2D(sampler, outTexCoords);";
        fs << "float noise = noiseParams.y*(fract(43758.5453*sin(dot(gl_FragCoord.xy,vec2(12.9898,78.233))+noiseParams.z))-0.5);";
        fs << "vec4 color = vec4(pixel.rgb + vec3(noise), pixel.a);";
        fs << "float s = noiseParams.x;";
        fs << "gl_FragColor = smoothstep(-s, 1.0+s, color);";
    } else if (isRegionEnabled(needs)) {
        fs  << "float r = 0.0;"
            << "if(regtype == 0){ //SQUARE/RECTANGLE"
            << "    r = length(outTexCoords.x - regPos.x)/regSize.x;"
            << "    r = max(r,length(outTexCoords.y - regPos.y)/regSize.y);"
            << "}"
            << "if(regtype == 1){ //CIRCLE/ELIPSE"
            << "    r = length((outTexCoords.xy - regPos)/regSize);"
            << "}"
            << "if (reginvert) { r = 1.0/(r+0.0001);};"
            //Nothing, just discard
            << "if (r < 1.0 - regTsize){ discard;}"
            //Degradation, reduce the pixel value
            //Zoom part
            << "vec2 coords = (outTexCoords.xy - regPos)*regFactor + regPos;"
            << "gl_FragColor = texture2D(sampler, coords);"
            << "if (r < 1.0 + regTsize){ gl_FragColor = gl_FragColor * ((r-(1.0-regTsize))/(2.0*regTsize+0.0001));}";
    } else {
        fs << "gl_FragColor = texture2D(sampler, outTexCoords);";
    }
    return fs;
}

} /* namespace android */
