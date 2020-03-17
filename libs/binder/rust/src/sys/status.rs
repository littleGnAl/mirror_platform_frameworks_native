/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::error::{binder_status, Result};
use crate::parcel::Parcel;
use crate::sys::libbinder_bindings::*;
use crate::utils::AsNative;

impl android_binder_Status {
    fn new() -> Self {
        android_binder_Status {
            mException: 0,
            mErrorCode: 0,
            mMessage: unsafe { android_String8::new() },
        }
    }
}

/// Wrapper for `android_binder::Status`.
// TODO: Do we want to rely on this being a POD type or should we treat it as an
// opaque pointer too?
#[repr(transparent)]
pub struct Status(android_binder_Status);

impl Status {
    pub fn from_parcel(parcel: &Parcel) -> Result<Self> {
        unsafe {
            let mut status = android_binder_Status::new();
            let err =
                android_binder_Status_readFromParcel(&mut status as *mut _, parcel.as_native());
            binder_status(err)?;
            Ok(Status(status))
        }
    }
}

impl From<Status> for Result<()> {
    fn from(status: Status) -> Self {
        // TODO: return both Exceptions and low level transaction codes
        binder_status(status.0.mErrorCode)
    }
}
