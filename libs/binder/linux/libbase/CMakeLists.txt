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
project(libbase CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")
include(AppendCxxFlagIfSupported)

set(CMAKE_CXX_STANDARD 20)

set(LIBBASE_CXX_FLAGS
    "-Wall"
    "-Wextra"
    "-fPIC"
    "-Wno-unknown-pragmas"
    "-Wno-attributes"
    "-Wno-ignored-attributes"
)

append_cxx_flag_if_supported(-Wno-vla-larger-than LIBBASE_CXX_FLAGS)

if (NOT LIBBASE_DIR AND ANDROID_BUILD_TOP)
    set(LIBBASE_DIR "${ANDROID_BUILD_TOP}/system/libbase")
endif()

if (NOT FMT_DIR AND ANDROID_BUILD_TOP)
    set(FMT_DIR "${ANDROID_BUILD_TOP}/external/fmtlib")
endif()
if (FMT_DIR)
    add_subdirectory("${FMT_DIR}" fmt EXCLUDE_FROM_ALL)
else()
    find_package(fmt REQUIRED)
endif()

set(LIBBASE_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/logging.cpp"
    #"${LIBBASE_DIR}/abi_compatibility.cpp"
    #"${LIBBASE_DIR}/chrono_utils.cpp"
    #"${LIBBASE_DIR}/cmsg.cpp"
    "${LIBBASE_DIR}/file.cpp"
    #"${LIBBASE_DIR}/hex.cpp"
    #"${LIBBASE_DIR}/mapped_file.cpp"
    #"${LIBBASE_DIR}/parsebool.cpp"
    #"${LIBBASE_DIR}/parsenetaddress.cpp"
    "${LIBBASE_DIR}/posix_strerror_r.cpp"
    #"${LIBBASE_DIR}/process.cpp"
    #"${LIBBASE_DIR}/properties.cpp"
    "${LIBBASE_DIR}/stringprintf.cpp"
    "${LIBBASE_DIR}/strings.cpp"
    #"${LIBBASE_DIR}/threads.cpp"
    #"${LIBBASE_DIR}/test_utils.cpp"
)

if (UNIX)
    list(APPEND LIBBASE_SRCS
        "${LIBBASE_DIR}/errors_unix.cpp")
endif(UNIX)

add_library(android_libbase ${LIBBASE_SRCS})

target_include_directories(android_libbase
    PUBLIC
    "${LIBBASE_DIR}/include")

target_link_libraries(android_libbase fmt::fmt)

target_compile_options(android_libbase PRIVATE ${LIBBASE_CXX_FLAGS})
