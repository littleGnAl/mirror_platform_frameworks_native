# Copyright 2015 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CLANG := true
LOCAL_CPPFLAGS := -std=c++14 -Weverything

# We only care about compiling as C++14
LOCAL_CPPFLAGS += -Wno-c++98-compat-pedantic

LOCAL_SRC_FILES := \
    Active.cpp

LOCAL_MODULE := active

LOCAL_MODULE_PATH := $(TARGET_OUT_DATA)/active
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := active
LOCAL_MODULE_STEM_64 := active64

LOCAL_SHARED_LIBRARIES := \
    libgui \
    libutils

include $(BUILD_EXECUTABLE)
