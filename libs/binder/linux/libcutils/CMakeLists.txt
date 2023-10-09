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
project(libcutils C CXX)

set(CMAKE_CXX_STANDARD 20)

if (NOT LIBCUTILS_DIR AND ANDROID_BUILD_TOP)
    set(LIBCUTILS_DIR "${ANDROID_BUILD_TOP}/system/core/libcutils")
endif()

if (NOT LIBUTILS_DIR AND ANDROID_BUILD_TOP)
    set(LIBUTILS_DIR "${ANDROID_BUILD_TOP}/system/core/libutils")
endif()

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../libbase" libbase EXCLUDE_FROM_ALL)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../liblog" liblog EXCLUDE_FROM_ALL)

add_library(android_libcutils INTERFACE)

target_include_directories(android_libcutils
    INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${LIBCUTILS_DIR}/include"
    "${LIBUTILS_DIR}/include"
)
