#!/bin/bash
# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ -n "$CLANG_TOOLS_BINDIR" ]; then
# On Trusty, use the bindgen from the prebuilts directory
BINDGEN="$CLANG_TOOLS_BINDIR/bindgen"
else
# On Android, use the bindgen from the host output directory
# (where this script is also located)
BINDGEN="`dirname $0`/bindgen"
fi

LIBBINDER_NDK_BINDGEN_ARGS=(
    # Unfortunately the only way to specify the rust_non_exhaustive enum
    # style for a type is to make it the default
    --default-enum-style="rust_non_exhaustive"
    # and then specify constified enums for the enums we don't want
    # rustified
    --constified-enum="android::c_interface::consts::.*"

    --allowlist-type="android::c_interface::.*"
    --allowlist-type="AStatus"
    --allowlist-type="AIBinder_Class"
    --allowlist-type="AIBinder"
    --allowlist-type="AIBinder_Weak"
    --allowlist-type="AIBinder_DeathRecipient"
    --allowlist-type="AParcel"
    --allowlist-type="binder_status_t"
    --allowlist-function=".*"
  )

exec $BINDGEN ${LIBBINDER_NDK_BINDGEN_ARGS[@]} "$@"
