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
project(aidl CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")
include(AppendCxxFlagIfSupported)

set(CMAKE_CXX_STANDARD 20)

set(AIDL_CXX_FLAGS
    "-Wall"
    "-Wextra"
    "-fPIC"
    "-fno-permissive"
    "-Wno-unknown-pragmas"
    "-Wno-comment"
    "-Wno-missing-field-initializers"
    "-Wno-return-type"
    "-Wno-uninitialized"
    "-Wno-attributes"
    "-Wno-array-bounds"
    "-Wno-range-loop-construct"
    "-Wno-ignored-attributes"
    "-Wno-int-in-bool-context"
)

append_cxx_flag_if_supported(-Wno-restrict AIDL_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-bool-compare AIDL_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-maybe-uninitialized AIDL_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-changes-meaning AIDL_CXX_FLAGS)

if (NOT AIDL_DIR AND ANDROID_BUILD_TOP)
    set(AIDL_DIR "${ANDROID_BUILD_TOP}/system/tools/aidl")
endif()

set(AIDL_SRCS
    "${AIDL_DIR}/main.cpp"
    "${AIDL_DIR}/aidl_checkapi.cpp"
    "${AIDL_DIR}/aidl_const_expressions.cpp"
    "${AIDL_DIR}/aidl_dumpapi.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/gen/aidl_language_l.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/gen/aidl_language_y.cpp"
    "${AIDL_DIR}/aidl_language.cpp"
    "${AIDL_DIR}/aidl_to_common.cpp"
    "${AIDL_DIR}/aidl_to_cpp_common.cpp"
    "${AIDL_DIR}/aidl_to_cpp.cpp"
    "${AIDL_DIR}/aidl_to_java.cpp"
    "${AIDL_DIR}/aidl_to_ndk.cpp"
    "${AIDL_DIR}/aidl_to_rust.cpp"
    "${AIDL_DIR}/aidl_typenames.cpp"
    "${AIDL_DIR}/aidl.cpp"
    "${AIDL_DIR}/ast_java.cpp"
    "${AIDL_DIR}/check_valid.cpp"
    "${AIDL_DIR}/code_writer.cpp"
    "${AIDL_DIR}/comments.cpp"
    "${AIDL_DIR}/diagnostics.cpp"
    "${AIDL_DIR}/generate_aidl_mappings.cpp"
    "${AIDL_DIR}/generate_cpp.cpp"
    "${AIDL_DIR}/generate_cpp_analyzer.cpp"
    "${AIDL_DIR}/generate_java_binder.cpp"
    "${AIDL_DIR}/generate_java.cpp"
    "${AIDL_DIR}/generate_ndk.cpp"
    "${AIDL_DIR}/generate_rust.cpp"
    "${AIDL_DIR}/import_resolver.cpp"
    "${AIDL_DIR}/io_delegate.cpp"
    "${AIDL_DIR}/location.cpp"
    "${AIDL_DIR}/logging.cpp"
    "${AIDL_DIR}/options.cpp"
    "${AIDL_DIR}/parser.cpp"
    "${AIDL_DIR}/permission.cpp"
    "${AIDL_DIR}/preprocess.cpp"
)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../libbase" libbase EXCLUDE_FROM_ALL)

add_executable(aidl ${AIDL_SRCS})

target_include_directories(aidl
    PUBLIC
    "${AIDL_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/gen"
)

cmake_policy(SET CMP0012 NEW)
find_package(GTest REQUIRED)

target_link_libraries(aidl
    android_libbase
    GTest::gtest
)

target_compile_options(aidl PRIVATE ${AIDL_CXX_FLAGS})
