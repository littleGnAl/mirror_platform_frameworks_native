/*
 * Copyright 2016 The Android Open Source Project
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

//#define LOG_NDEBUG 1
#define LOG_TAG "GraphicsEnv"
#include <gui/GraphicsEnv.h>

#include <mutex>

#include <log/log.h>
#include <dlext_namespaces.h> // system/core/libnativeloader

namespace android {

/*static*/ GraphicsEnv& GraphicsEnv::getInstance() {
    static GraphicsEnv env;
    return env;
}

void GraphicsEnv::setDriverPath(const std::string path) {
    if (!mDriverPath.empty()) {
        ALOGV("ignoring attempt to change driver path from '%s' to '%s'",
                mDriverPath.c_str(), path.c_str());
        return;
    }
    ALOGV("setting driver path to '%s'", path.c_str());
    mDriverPath = path;
}

android_namespace_t* GraphicsEnv::getDriverNamespace() {
    static std::once_flag once;
    std::call_once(once, [this]() {
        if (!mDriverPath.empty()) {
            mDriverNamespace = android_create_namespace(
                    "gfx driver",
                    nullptr,                    // ld_library_path
                    mDriverPath.c_str(),        // default_library_path
                    ANDROID_NAMESPACE_TYPE_CHILD,
                    nullptr,                    // permitted_when_isolated_path
                    nullptr);                   // parent
        }
    });
    return mDriverNamespace;
}

} // namespace android
