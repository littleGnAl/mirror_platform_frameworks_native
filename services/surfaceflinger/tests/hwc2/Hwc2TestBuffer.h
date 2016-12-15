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

#ifndef _HWC2_TEST_BUFFER_H
#define _HWC2_TEST_BUFFER_H

#include <android-base/unique_fd.h>
#include <hardware/hwcomposer2.h>

class Hwc2TestBufferGenerator;

class Hwc2TestBuffer {
public:
    Hwc2TestBuffer();
    ~Hwc2TestBuffer();

    void updateBufferArea(int32_t bufferWidth, int32_t bufferHeight);

    int  get(buffer_handle_t* outHandle, int32_t* outFence);

    void setFence(int32_t fence);

protected:
    void closeFence();

    std::unique_ptr<Hwc2TestBufferGenerator> mBufferGenerator;

    int32_t mBufferWidth = -1;
    int32_t mBufferHeight = -1;

    std::mutex mMutex;
    std::condition_variable mCv;

    bool mPending = false;
    buffer_handle_t mHandle = nullptr;
    int32_t mFence = -1;
};

#endif /* ifndef _HWC2_TEST_BUFFER_H */
