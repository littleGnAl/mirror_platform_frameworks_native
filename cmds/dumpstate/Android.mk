LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := libdumpstate_default.c
LOCAL_MODULE := libdumpstate.default
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

ifdef BOARD_WLAN_DEVICE
LOCAL_CFLAGS := -DFWDUMP_$(BOARD_WLAN_DEVICE)
endif

LOCAL_SRC_FILES := dumpstate.c utils.c

LOCAL_MODULE := dumpstate

LOCAL_SHARED_LIBRARIES := libcutils liblog libselinux
LOCAL_HAL_STATIC_LIBRARIES := libdumpstate
LOCAL_CFLAGS += -Wall -Wno-unused-parameter -std=gnu99
LOCAL_REQUIRED_MODULES := dumpstate.rc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := dumpstate.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/init

include $(BUILD_PREBUILT)
