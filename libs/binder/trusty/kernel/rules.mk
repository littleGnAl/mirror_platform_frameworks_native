# Copyright (C) 2022 The Android Open Source Project
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

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

LIBBINDER_DIR := frameworks/native/libs/binder
LIBBASE_DIR := system/libbase
LIBCUTILS_DIR := system/core/libcutils
LIBUTILS_DIR := system/core/libutils
FMTLIB_DIR := external/fmtlib

MODULE_SRCS := \
	$(LOCAL_DIR)/../logging.cpp \
	$(LOCAL_DIR)/../TrustyStatus.cpp \
	$(LIBBINDER_DIR)/Binder.cpp \
	$(LIBBINDER_DIR)/BpBinder.cpp \
	$(LIBBINDER_DIR)/FdTrigger.cpp \
	$(LIBBINDER_DIR)/IInterface.cpp \
	$(LIBBINDER_DIR)/IResultReceiver.cpp \
	$(LIBBINDER_DIR)/OS_android.cpp \
	$(LIBBINDER_DIR)/Parcel.cpp \
	$(LIBBINDER_DIR)/Stability.cpp \
	$(LIBBINDER_DIR)/Status.cpp \
	$(LIBBINDER_DIR)/Utils.cpp \
	$(LIBBASE_DIR)/hex.cpp \
	$(LIBBASE_DIR)/stringprintf.cpp \
	$(LIBUTILS_DIR)/binder/Errors.cpp \
	$(LIBUTILS_DIR)/binder/RefBase.cpp \
	$(LIBUTILS_DIR)/binder/SharedBuffer.cpp \
	$(LIBUTILS_DIR)/binder/String16.cpp \
	$(LIBUTILS_DIR)/binder/String8.cpp \
	$(LIBUTILS_DIR)/binder/StrongPointer.cpp \
	$(LIBUTILS_DIR)/binder/Unicode.cpp \
	$(LIBUTILS_DIR)/binder/VectorImpl.cpp \
	$(LIBUTILS_DIR)/misc.cpp \

MODULE_DEFINES += \
	LK_DEBUGLEVEL_NO_ALIASES=1 \

MODULE_INCLUDES += \
	$(LOCAL_DIR)/.. \

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \
	$(LOCAL_DIR)/../include \
	$(LIBBINDER_DIR)/include \
	$(LIBBINDER_DIR)/ndk/include_cpp \
	$(LIBBASE_DIR)/include \
	$(LIBCUTILS_DIR)/include \
	$(LIBUTILS_DIR)/include \
	$(FMTLIB_DIR)/include \

GLOBAL_COMPILEFLAGS += \
	-DANDROID_BASE_UNIQUE_FD_DISABLE_IMPLICIT_CONVERSION \
	-DBINDER_NO_KERNEL_IPC \
	-DBINDER_RPC_SINGLE_THREADED \
	-D__ANDROID_VNDK__ \

MODULE_DEPS += \
	trusty/kernel/lib/libcxx-trusty \
	trusty/kernel/lib/libcxxabi-trusty \

include make/module.mk
