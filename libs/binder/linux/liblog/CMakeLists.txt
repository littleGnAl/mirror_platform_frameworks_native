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
project(liblog CXX)

set(CMAKE_CXX_STANDARD 17)

set(LIBLOG_CXX_FLAGS
    "-Wall"
    "-Werror"
    "-Wextra"
    "-Wno-exit-time-destructors"
    "-Wno-unused-parameter"
    "-fPIC"
)

set(LIBLOG_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/logger_write.cpp"
)

add_library(android_liblog ${LIBLOG_SRCS})

target_include_directories(android_liblog
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../trusty/include"
)

target_compile_options(android_liblog PRIVATE ${LIBLOG_CXX_FLAGS})
