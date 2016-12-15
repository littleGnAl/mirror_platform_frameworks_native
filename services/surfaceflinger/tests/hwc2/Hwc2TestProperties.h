/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _HWC2_TEST_PROPERTIES_H
#define _HWC2_TEST_PROPERTIES_H

#include <array>
#include <vector>

#define HWC2_INCLUDE_STRINGIFICATION
#define HWC2_USE_CPP11
#include <hardware/hwcomposer2.h>
#undef HWC2_INCLUDE_STRINGIFICATION
#undef HWC2_USE_CPP11

#include "Hwc2TestBuffer.h"

typedef enum {
    HWC2_TEST_COVERAGE_DEFAULT = 0,
    HWC2_TEST_COVERAGE_BASIC,
    HWC2_TEST_COVERAGE_COMPLETE,
    HWC2_TEST_NUM_COVERAGE_TYPES,
} hwc2_test_coverage_t;


class Hwc2TestContainer {
public:
    virtual ~Hwc2TestContainer() = default;

    /* Resets the container */
    virtual void reset() = 0;

    /* Attempts to advance to the next valid value. Returns true if one can be
     * found */
    virtual bool advance() = 0;

    virtual std::string dump() const = 0;
};


template <class T>
class Hwc2TestProperty : public Hwc2TestContainer {
public:
    Hwc2TestProperty(hwc2_test_coverage_t coverage,
            const std::vector<T>& completeList, const std::vector<T>& basicList,
            const std::vector<T>& defaultList)
        : Hwc2TestProperty((coverage == HWC2_TEST_COVERAGE_COMPLETE)? completeList:
                (coverage == HWC2_TEST_COVERAGE_BASIC)? basicList : defaultList) { }

    Hwc2TestProperty(const std::vector<T>& list)
        : mList(list) { }

    void reset() override
    {
        mListIdx = 0;
    }

    bool advance() override
    {
        if (mListIdx + 1 < mList.size()) {
            mListIdx++;
            updateDependents();
            return true;
        }
        reset();
        updateDependents();
        return false;
    }

    T get() const
    {
        return mList.at(mListIdx);
    }

protected:
    /* If a derived class has dependents, override this function */
    virtual void updateDependents() { }

    const std::vector<T>& mList;
    size_t mListIdx = 0;
};


class Hwc2TestSourceCrop;
class Hwc2TestSurfaceDamage;

class Hwc2TestBufferArea : public Hwc2TestProperty<std::pair<int32_t, int32_t>> {
public:
    Hwc2TestBufferArea(hwc2_test_coverage_t coverage, int32_t displayWidth,
            int32_t displayHeight);

    std::string dump() const;

    void setDependent(Hwc2TestBuffer* buffer);
    void setDependent(Hwc2TestSourceCrop* source_crop);
    void setDependent(Hwc2TestSurfaceDamage* surfaceDamage);

protected:
    void update();
    void updateDependents();

    const std::vector<float>& mScalars;
    static const std::vector<float> mDefaultScalars;
    static const std::vector<float> mBasicScalars;
    static const std::vector<float> mCompleteScalars;

    int32_t mDisplayWidth;
    int32_t mDisplayHeight;

    Hwc2TestBuffer* mBuffer = nullptr;
    Hwc2TestSourceCrop* mSourceCrop = nullptr;
    Hwc2TestSurfaceDamage* mSurfaceDamage = nullptr;

    std::vector<std::pair<int32_t, int32_t>> mBufferAreas;
};


class Hwc2TestBlendMode : public Hwc2TestProperty<hwc2_blend_mode_t> {
public:
    Hwc2TestBlendMode(hwc2_test_coverage_t coverage);

    std::string dump() const;

protected:
    static const std::vector<hwc2_blend_mode_t> mDefaultBlendModes;
    static const std::vector<hwc2_blend_mode_t> mBasicBlendModes;
    static const std::vector<hwc2_blend_mode_t> mCompleteBlendModes;
};


class Hwc2TestColor : public Hwc2TestProperty<hwc_color_t> {
public:
    Hwc2TestColor(hwc2_test_coverage_t coverage);

    std::string dump() const;

protected:
    static const std::vector<hwc_color_t> mDefaultColors;
    static const std::vector<hwc_color_t> mBasicColors;
    static const std::vector<hwc_color_t> mCompleteColors;
};


class Hwc2TestComposition : public Hwc2TestProperty<hwc2_composition_t> {
public:
    Hwc2TestComposition(hwc2_test_coverage_t coverage);

    std::string dump() const;

protected:
    static const std::vector<hwc2_composition_t> mDefaultCompositions;
    static const std::vector<hwc2_composition_t> mBasicCompositions;
    static const std::vector<hwc2_composition_t> mCompleteCompositions;
};


class Hwc2TestCursor : public Hwc2TestProperty<std::pair<int32_t, int32_t>> {
public:
    Hwc2TestCursor(hwc2_test_coverage_t coverage, int32_t displayWidth,
            int32_t displayHeight);

    std::string dump() const;

protected:
    void update();

    const std::vector<float>& mScalars;
    static const std::vector<float> mDefaultScalars;
    static const std::vector<float> mBasicScalars;
    static const std::vector<float> mCompleteScalars;

    int32_t mDisplayWidth;
    int32_t mDisplayHeight;

    std::vector<std::pair<int32_t, int32_t>> mCursors;
};


class Hwc2TestDataspace : public Hwc2TestProperty<android_dataspace_t> {
public:
    Hwc2TestDataspace(hwc2_test_coverage_t coverage);

    std::string dump() const;

protected:
    static const std::vector<android_dataspace_t> defaultDataspaces;
    static const std::vector<android_dataspace_t> basicDataspaces;
    static const std::vector<android_dataspace_t> completeDataspaces;
};


class Hwc2TestDisplayFrame : public Hwc2TestProperty<hwc_rect_t> {
public:
    Hwc2TestDisplayFrame(hwc2_test_coverage_t coverage,
            int32_t displayWidth, int32_t displayHeight);

    std::string dump() const;

protected:
    void update();

    const std::vector<hwc_frect_t>& mFrectScalars;
    const static std::vector<hwc_frect_t> mDefaultFrectScalars;
    const static std::vector<hwc_frect_t> mBasicFrectScalars;
    const static std::vector<hwc_frect_t> mCompleteFrectScalars;

    int32_t mDisplayWidth;
    int32_t mDisplayHeight;

    std::vector<hwc_rect_t> mDisplayFrames;
};


class Hwc2TestPlaneAlpha : public Hwc2TestProperty<float> {
public:
    Hwc2TestPlaneAlpha(hwc2_test_coverage_t coverage);

    std::string dump() const;

protected:
    static const std::vector<float> mDefaultPlaneAlphas;
    static const std::vector<float> mBasicPlaneAlphas;
    static const std::vector<float> mCompletePlaneAlphas;
};


class Hwc2TestSourceCrop : public Hwc2TestProperty<hwc_frect_t> {
public:
    Hwc2TestSourceCrop(hwc2_test_coverage_t coverage, float bufferWidth = 0,
            float bufferHeight = 0);

    std::string dump() const;

    void updateBufferArea(float bufferWidth, float bufferHeight);

protected:
    void update();

    const std::vector<hwc_frect_t>& mFrectScalars;
    const static std::vector<hwc_frect_t> mDefaultFrectScalars;
    const static std::vector<hwc_frect_t> mBasicFrectScalars;
    const static std::vector<hwc_frect_t> mCompleteFrectScalars;

    float mBufferWidth;
    float mBufferHeight;

    std::vector<hwc_frect_t> mSourceCrops;
};


class Hwc2TestSurfaceDamage : public Hwc2TestProperty<hwc_region_t> {
public:
    Hwc2TestSurfaceDamage(hwc2_test_coverage_t coverage);
    ~Hwc2TestSurfaceDamage();

    std::string dump() const;

    void updateBufferArea(int32_t bufferWidth, int32_t bufferHeight);

protected:
    void update();
    void freeSurfaceDamages();

    const std::vector<std::vector<hwc_frect_t>> &mRegionScalars;
    const static std::vector<std::vector<hwc_frect_t>> mDefaultRegionScalars;
    const static std::vector<std::vector<hwc_frect_t>> mBasicRegionScalars;
    const static std::vector<std::vector<hwc_frect_t>> mCompleteRegionScalars;

    int32_t mBufferWidth = 0;
    int32_t mBufferHeight = 0;

    std::vector<hwc_region_t> mSurfaceDamages;
};


class Hwc2TestTransform : public Hwc2TestProperty<hwc_transform_t> {
public:
    Hwc2TestTransform(hwc2_test_coverage_t coverage);

    std::string dump() const;

protected:
    static const std::vector<hwc_transform_t> mDefaultTransforms;
    static const std::vector<hwc_transform_t> mBasicTransforms;
    static const std::vector<hwc_transform_t> mCompleteTransforms;
};

#endif /* ifndef _HWC2_TEST_PROPERTIES_H */
