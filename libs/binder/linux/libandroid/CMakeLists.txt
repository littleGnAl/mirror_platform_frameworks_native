# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 3.18)

include_guard(GLOBAL)
project(libandroid CXX)

set(CMAKE_CXX_STANDARD 20)

add_library(android_libandroid_headers INTERFACE)
target_include_directories(android_libandroid_headers INTERFACE
    "${ANDROID_BUILD_TOP}/frameworks/native/include"
)

set(LIBANDROID_DIR "${ANDROID_BUILD_TOP}/frameworks/base/native/android")
set(LIBANDROID_SRCS
    #"activity_manager.cpp",
    #"asset_manager.cpp",
    #"choreographer.cpp",
    #"configuration.cpp",
    #"hardware_buffer_jni.cpp",
    #"input.cpp",
    #"looper.cpp",
    #"native_activity.cpp",
    #"native_window_jni.cpp",
    #"net.c",
    #"obb.cpp",
    #"permission_manager.cpp",
    #"performance_hint.cpp",
    #"sensor.cpp",
    #"sharedmem.cpp",
    #"storage_manager.cpp",
    #"surface_control.cpp",
    #"surface_texture.cpp",
    #"system_fonts.cpp",
    #"${LIBANDROID_DIR}/trace.cpp"
    #"thermal.cpp",
)

#add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../libcutils" libcutils EXCLUDE_FROM_ALL)
#add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../liblog" liblog EXCLUDE_FROM_ALL)

add_library(android_libandroid INTERFACE)

target_include_directories(android_libandroid
    INTERFACE
    "${LIBANDROID_DIR}/include"
    "${ANDROID_BUILD_TOP}/system/core/libcutils/include"
)
