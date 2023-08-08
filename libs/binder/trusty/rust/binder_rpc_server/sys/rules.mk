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

LOCAL_DIR := $(GET_LOCAL_DIR)
LIBBINDER_DIR := $(LOCAL_DIR)/../../../..

MODULE := $(LOCAL_DIR)

MODULE_SRCS := $(LOCAL_DIR)/lib.rs

MODULE_CRATE_NAME := binder_rpc_server_sys

MODULE_LIBRARY_DEPS += \
	$(LOCAL_DIR)/cpp \
	trusty/user/base/lib/trusty-sys \

MODULE_BINDGEN_SRC_HEADER := \
	$(LIBBINDER_DIR)/trusty/include_rust/binder/RpcServerTrustyRust.h

MODULE_BINDGEN_FLAGS += \
	--allowlist-type="RpcServerTrustyRust" \
	--allowlist-function="RpcServerTrustyRust_.*" \

include make/library.mk