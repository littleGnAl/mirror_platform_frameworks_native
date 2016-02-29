LOCAL_PATH:= $(call my-dir)

svc_c_flags =	\
	-Wall -Wextra \

ifneq ($(TARGET_USES_64_BIT_BINDER),true)
ifneq ($(TARGET_IS_64_BIT),true)
svc_c_flags += -DBINDER_IPC_32BIT=1
endif
endif

include $(CLEAR_VARS)
LOCAL_MODULE := libcbinder
LOCAL_SRC_FILES := binder.c
LOCAL_CFLAGS := -Werror $(svc_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_STATIC_LIBRARIES := libcbinder
LOCAL_SRC_FILES := bctest.c
LOCAL_CFLAGS += $(svc_c_flags)
LOCAL_MODULE := bctest
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SHARED_LIBRARIES := liblog libselinux
LOCAL_STATIC_LIBRARIES := libcbinder
LOCAL_SRC_FILES := service_manager.c
LOCAL_CFLAGS += $(svc_c_flags)
LOCAL_MODULE := servicemanager
LOCAL_INIT_RC := servicemanager.rc
include $(BUILD_EXECUTABLE)
