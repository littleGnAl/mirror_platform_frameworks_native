#
# Copyright (C) 2014 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += \
    libutils \
    liblog \
    libbinder

LOCAL_C_INCLUDES += \
    frameworks/base/include

LOCAL_CFLAGS += -std=gnu++11 -Werror -Wextra
LOCAL_MODULE := newservicemanager
LOCAL_SRC_FILES := new_svc.cpp
include external/libcxx/libcxx.mk
include $(BUILD_EXECUTABLE)
