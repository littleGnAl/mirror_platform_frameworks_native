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

use std::result;

use binder_rs_sys::*;
use crate::parcel::Parcel;
use crate::utils::AsNative;

pub use binder_rs_sys::android_status_t as status_t;

/// Error codes from Android `libutils`.
// All error codes are negative integer values. Derived from the anonymous enum
// in utils/Errors.h
pub use binder_rs_sys::android_c_interface_Error as Error;

/// A specialized [`Result`](result::Result) for binder operations.
pub type Result<T> = result::Result<T, Error>;

/// Convert a native [`status_t`] error code to the idiomatic Rust result type
pub fn binder_status(status: status_t) -> Result<()> {
    if status == Error::OK as i32 {
        Ok(())
    } else if status == Error::NO_MEMORY as i32 {
        Err(Error::NO_MEMORY)
    } else if status == Error::INVALID_OPERATION as i32 {
        Err(Error::INVALID_OPERATION)
    } else if status == Error::BAD_VALUE as i32 {
        Err(Error::BAD_VALUE)
    } else if status == Error::BAD_TYPE as i32 {
        Err(Error::BAD_TYPE)
    } else if status == Error::NAME_NOT_FOUND as i32 {
        Err(Error::NAME_NOT_FOUND)
    } else if status == Error::PERMISSION_DENIED as i32 {
        Err(Error::PERMISSION_DENIED)
    } else if status == Error::NO_INIT as i32 {
        Err(Error::NO_INIT)
    } else if status == Error::ALREADY_EXISTS as i32 {
        Err(Error::ALREADY_EXISTS)
    } else if status == Error::DEAD_OBJECT as i32 {
        Err(Error::DEAD_OBJECT)
    } else if status == Error::FAILED_TRANSACTION as i32 {
        Err(Error::FAILED_TRANSACTION)
    } else if status == Error::BAD_INDEX as i32 {
        Err(Error::BAD_INDEX)
    } else if status == Error::NOT_ENOUGH_DATA as i32 {
        Err(Error::NOT_ENOUGH_DATA)
    } else if status == Error::WOULD_BLOCK as i32 {
        Err(Error::WOULD_BLOCK)
    } else if status == Error::TIMED_OUT as i32 {
        Err(Error::TIMED_OUT)
    } else if status == Error::UNKNOWN_TRANSACTION as i32 {
        Err(Error::UNKNOWN_TRANSACTION)
    } else if status == Error::FDS_NOT_ALLOWED as i32 {
        Err(Error::FDS_NOT_ALLOWED)
    } else if status == Error::UNEXPECTED_NULL as i32 {
        Err(Error::UNEXPECTED_NULL)
    } else {
        Err(Error::UNKNOWN_ERROR)
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
            let mut status = android_binder_Status {
                mException: 0,
                mErrorCode: 0,
                mMessage: android_String8::new(),
            };
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
