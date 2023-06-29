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

include_guard(GLOBAL)
project(libcutils C CXX)

set(CMAKE_CXX_STANDARD 20)

set(LIBCUTILS_CXX_FLAGS
    "-Wall"
    "-Wextra"
    "-Wno-exit-time-destructors"
    "-fPIC"
    "-Wno-missing-field-initializers"
    "-Wno-type-limits"
    "-Wno-invalid-offsetof"
)

if (NOT LIBCUTILS_DIR AND ANDROID_BUILD_TOP)
    set(LIBCUTILS_DIR "${ANDROID_BUILD_TOP}/system/core/libcutils")
endif()

if (NOT LIBUTILS_DIR AND ANDROID_BUILD_TOP)
    set(LIBUTILS_DIR "${ANDROID_BUILD_TOP}/system/core/libutils")
endif()

set(LIBCUTILS_COMMON_SRCS
    "${LIBCUTILS_DIR}/config_utils.cpp"
    "${LIBCUTILS_DIR}/iosched_policy.cpp"
    "${LIBCUTILS_DIR}/load_file.cpp"
    "${LIBCUTILS_DIR}/native_handle.cpp"
    "${LIBCUTILS_DIR}/properties.cpp"
    "${LIBCUTILS_DIR}/record_stream.cpp"
    "${LIBCUTILS_DIR}/strlcpy.c"
    "${LIBCUTILS_DIR}/threads.cpp"
)

set(LIBCUTILS_SRCS
	${LIBCUTILS_COMMON_SRCS}
    "${LIBCUTILS_DIR}/fs.cpp"
    "${LIBCUTILS_DIR}/hashmap.cpp"
    "${LIBCUTILS_DIR}/multiuser.cpp"
    "${LIBCUTILS_DIR}/str_parms.cpp"
	"${LIBCUTILS_DIR}/ashmem-host.cpp"
	"${LIBCUTILS_DIR}/canned_fs_config.cpp"
	"${LIBCUTILS_DIR}/fs_config.cpp"
	"${LIBCUTILS_DIR}/trace-host.cpp"
)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../libbase" libbase EXCLUDE_FROM_ALL)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../liblog" liblog EXCLUDE_FROM_ALL)

add_library(android_libcutils ${LIBCUTILS_SRCS})

target_include_directories(android_libcutils
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${LIBCUTILS_DIR}/include"
    "${LIBUTILS_DIR}/include"
)

target_link_libraries(android_libcutils android_libbase android_liblog)

target_compile_options(android_libcutils PRIVATE ${LIBCUTILS_CXX_FLAGS})
