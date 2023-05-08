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
BINDER_RUST_DIR := frameworks/native/libs/binder/rust

MODULE := $(LOCAL_DIR)

MODULE_SRCS := $(BINDER_RUST_DIR)/sys/lib.rs

MODULE_CRATE_NAME := binder_ndk_sys

MODULE_LIBRARY_DEPS += \
	frameworks/native/libs/binder/trusty \
	frameworks/native/libs/binder/trusty/ndk \
	trusty/user/base/lib/trusty-sys \

MODULE_BINDGEN_SRC_HEADER := $(BINDER_RUST_DIR)/sys/BinderBindings.hpp

MODULE_CUSTOM_BINDGEN := $(BINDER_RUST_DIR)/libbinder_ndk_bindgen.sh

include make/library.mk
