/*
 * Copyright (C) 2023 The Android Open Source Project
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

//! Rust wrapper for AHardwareBuffer.

use binder::{
    binder_impl::{
        BorrowedParcel, Deserialize, DeserializeArray, DeserializeOption, Serialize,
        SerializeArray, SerializeOption, NON_NULL_PARCELABLE_FLAG, NULL_PARCELABLE_FLAG,
    },
    unstable_api::{status_result, AsNative},
    StatusCode,
};
use nativewindow_bindgen::{
    AHardwareBuffer, AHardwareBuffer_getId, AHardwareBuffer_readFromParcel,
    AHardwareBuffer_release, AHardwareBuffer_writeToParcel,
};
use std::{
    fmt::{self, Debug, Formatter},
    ptr::{null_mut, NonNull},
};

/// Rust wrapper for `AHardwareBuffer`.
pub struct HardwareBuffer {
    buffer: NonNull<AHardwareBuffer>,
}

impl HardwareBuffer {
    /// Returns the system-wide unique ID for the underlying `AHardwareBuffer`.
    pub fn id(&self) -> u64 {
        let mut id = 0;

        // SAFETY: The AHardwareBuffer pointer we pass is guaranteed to be non-null and valid
        // because it must have been allocated by `AHardwareBuffer_readFromParcel` and we have not
        // yet released it. The id pointer must be valid because it comes from a reference.
        let status = unsafe { AHardwareBuffer_getId(self.buffer.as_ptr(), &mut id) };

        // Status should only be non-zero if we passed a null pointer, which we didn't.
        assert_eq!(status, 0);

        id
    }
}

// SAFETY: `AHardwareBuffer` doesn't have anything specific to a particular thread.
unsafe impl Send for HardwareBuffer {}

// SAFETY: None of the methods we expose give interior mutability.
unsafe impl Sync for HardwareBuffer {}

impl Debug for HardwareBuffer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "HardwareBuffer {}", self.id())
    }
}

impl Serialize for HardwareBuffer {
    fn serialize(&self, parcel: &mut BorrowedParcel) -> Result<(), StatusCode> {
        SerializeOption::serialize_option(Some(self), parcel)
    }
}

impl SerializeOption for HardwareBuffer {
    fn serialize_option(
        this: Option<&Self>,
        parcel: &mut BorrowedParcel,
    ) -> Result<(), StatusCode> {
        if let Some(this) = this {
            parcel.write(&NON_NULL_PARCELABLE_FLAG)?;

            // SAFETY: The AHardwareBuffer pointer we pass is guaranteed to be non-null and valid
            // because it must have been allocated by `AHardwareBuffer_readFromParcel` and we have
            // not yet released it.
            let status = unsafe {
                AHardwareBuffer_writeToParcel(this.buffer.as_ptr(), parcel.as_native_mut())
            };
            status_result(status)
        } else {
            parcel.write(&NULL_PARCELABLE_FLAG)
        }
    }
}

impl Deserialize for HardwareBuffer {
    type UninitType = Option<Self>;

    fn uninit() -> Option<Self> {
        None
    }

    fn from_init(value: Self) -> Option<Self> {
        Some(value)
    }

    fn deserialize(parcel: &BorrowedParcel) -> Result<Self, StatusCode> {
        DeserializeOption::deserialize_option(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeOption for HardwareBuffer {
    fn deserialize_option(parcel: &BorrowedParcel) -> Result<Option<Self>, StatusCode> {
        let present: i32 = parcel.read()?;
        match present {
            NULL_PARCELABLE_FLAG => Ok(None),
            NON_NULL_PARCELABLE_FLAG => {
                let mut buffer = null_mut();

                let status =
                // SAFETY: Both pointers must be valid because they are obtained from references.
                // `AHardwareBuffer_readFromParcel` doesn't store them or do anything else special
                // with them. If it returns success then it will have allocated a new
                // `AHardwareBuffer` and incremented the reference count, so we can use it until we
                // release it.
                    unsafe { AHardwareBuffer_readFromParcel(parcel.as_native(), &mut buffer) };

                status_result(status)?;

                Ok(Some(Self {
                    buffer: NonNull::new(buffer).expect(
                        "AHardwareBuffer_readFromParcel returned success but didn't allocate buffer",
                    ),
                }))
            }
            _ => Err(StatusCode::BAD_VALUE),
        }
    }
}

impl SerializeArray for HardwareBuffer {}

impl DeserializeArray for HardwareBuffer {}

impl Drop for HardwareBuffer {
    fn drop(&mut self) {
        // SAFETY: The AHardwareBuffer pointer we pass is guaranteed to be non-null and valid
        // because it must have been allocated by `AHardwareBuffer_readFromParcel` and we have
        // not yet released it.
        unsafe {
            AHardwareBuffer_release(self.buffer.as_ptr());
        }
    }
}
