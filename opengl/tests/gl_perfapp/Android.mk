#########################################################################
# OpenGL ES Perf App
# This makefile builds both an activity and a shared library.
#########################################################################
TOP_LOCAL_PATH:= $(call my-dir)

# Build activity

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-subdir-java-files)

LOCAL_PACKAGE_NAME := GLPerf

LOCAL_JNI_SHARED_LIBRARIES := libglperf

# Run on Eclair
LOCAL_SDK_VERSION := 7

include $(BUILD_PACKAGE)

#########################################################################
# Build JNI Shared Library
#########################################################################

LOCAL_PATH:= $(LOCAL_PATH)/jni

include $(CLEAR_VARS)

LOCAL_CFLAGS := -Werror -Wno-error=unused-parameter

LOCAL_SRC_FILES:= \
  gl_code.cpp

LOCAL_C_INCLUDES := $(JNI_H_INCLUDE)

LOCAL_SHARED_LIBRARIES := \
	libutils \
	liblog \
	libEGL \
	libGLESv2

LOCAL_MODULE := libglperf



include $(BUILD_SHARED_LIBRARY)
