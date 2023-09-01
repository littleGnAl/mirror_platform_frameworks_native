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
    binder_impl::{BorrowedParcel, Deserialize, Serialize},
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
#[derive(Default)]
pub struct HardwareBuffer {
    buffer: Option<NonNull<AHardwareBuffer>>,
}

impl HardwareBuffer {
    /// Returns the system-wide unique ID for the underlying `AHardwareBuffer`.
    pub fn id(&self) -> Option<u64> {
        let buffer = self.buffer?;
        let mut id = 0;

        // SAFETY: The AHardwareBuffer pointer we pass is guaranteed to be non-null and valid
        // because it must have been allocated by `AHardwareBuffer_readFromParcel` and we have not
        // yet released it. The id pointer must be valid because it comes from a reference.
        let status = unsafe { AHardwareBuffer_getId(buffer.as_ptr(), &mut id) };

        // Status should only be non-zero if we passed a null pointer, which we didn't.
        assert_eq!(status, 0);

        Some(id)
    }
}

// SAFETY: `AHardwareBuffer` doesn't have anything specific to a particular thread.
unsafe impl Send for HardwareBuffer {}

impl Debug for HardwareBuffer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Some(id) = self.id() {
            write!(f, "HardwareBuffer {}", id)
        } else {
            f.write_str("HardwareBuffer: Invalid")
        }
    }
}

impl Serialize for HardwareBuffer {
    fn serialize(&self, parcel: &mut BorrowedParcel) -> Result<(), StatusCode> {
        // SAFETY: The AHardwareBuffer pointer we pass is guaranteed to be non-null and valid
        // because it must have been allocated by `AHardwareBuffer_readFromParcel` and we have not
        // yet released it.
        let status = unsafe {
            AHardwareBuffer_writeToParcel(
                self.buffer.expect("Tried to serialize uninitialised HardwareBuffer").as_ptr(),
                parcel.as_native_mut(),
            )
        };

        status_result(status)
    }
}

impl Deserialize for HardwareBuffer {
    type UninitType = Self;

    fn uninit() -> Self {
        Default::default()
    }

    fn from_init(value: Self) -> Self {
        value
    }

    fn deserialize(parcel: &BorrowedParcel) -> Result<Self, StatusCode> {
        let mut buffer = null_mut();

        // SAFETY: Both pointers must be valid because they are obtained from references.
        // `AHardwareBuffer_readFromParcel` doesn't store them or do anything else special with
        // them. If it returns success then it will have allocated a new `AHardwareBuffer` and
        // incremented the reference count, so we can use it until we release it.
        let status = unsafe { AHardwareBuffer_readFromParcel(parcel.as_native(), &mut buffer) };

        status_result(status)?;

        Ok(Self { buffer: NonNull::new(buffer) })
    }
}

impl Drop for HardwareBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer {
            // SAFETY: The AHardwareBuffer pointer we pass is guaranteed to be non-null and valid
            // because it must have been allocated by `AHardwareBuffer_readFromParcel` and we have
            // not yet released it.
            unsafe {
                AHardwareBuffer_release(buffer.as_ptr());
            }
        }
    }
}
