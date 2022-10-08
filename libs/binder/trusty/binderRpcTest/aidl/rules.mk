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

LIBBINDER_TEST_DIR := frameworks/native/libs/binder/tests

MODULE_AIDLS := \
	$(LIBBINDER_TEST_DIR)/BinderRpcTestClientInfo.aidl \
	$(LIBBINDER_TEST_DIR)/BinderRpcTestServerConfig.aidl \
	$(LIBBINDER_TEST_DIR)/BinderRpcTestServerInfo.aidl \
	$(LIBBINDER_TEST_DIR)/IBinderRpcCallback.aidl \
	$(LIBBINDER_TEST_DIR)/IBinderRpcSession.aidl \
	$(LIBBINDER_TEST_DIR)/IBinderRpcTest.aidl \
	$(LIBBINDER_TEST_DIR)/ParcelableCertificateData.aidl \

include make/aidl.mk
