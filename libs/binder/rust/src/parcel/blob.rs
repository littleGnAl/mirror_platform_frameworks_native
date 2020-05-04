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

use binder_rs_sys::*;
use crate::utils::AsNative;

use std::ptr::NonNull;

// We enforce an im/mutable reference & lifetime through the type system so that
// Blob does not outlive its creator. This is because for small strings, the Blob
// will point into the Parcel's buffer and we want to handle that
// scenario even if it may own allocations of larger strings.
/// A read-only binary blob of data that can be read from a
/// [`Parcel`](super::Parcel)
///
/// A `ReadableBlob` is produced by the
/// [`Parcel::read_blob`](super::Parcel::read_blob) method.
pub struct ReadableBlob<'a>(&'a mut android_Parcel_ReadableBlob);
/// A writable binary blob of data that will be sent in a
/// [`Parcel`](super::Parcel)
///
/// A `WritableBlob` is created by the
/// [`Parcel::write_blob`](super::Parcel::write_blob) method.
pub struct WritableBlob<'a>(&'a mut android_Parcel_WritableBlob);

pub(super) trait Blob {
    type Ptr;

    fn from_ptr(blob: *mut Self::Ptr) -> Self;

    fn clear(&mut self);

    fn release(&mut self);
}

unsafe impl AsNative<android_Parcel_ReadableBlob> for ReadableBlob<'_> {
    fn as_native(&self) -> *const android_Parcel_ReadableBlob {
        self.0 as *const _
    }

    fn as_native_mut(&mut self) -> *mut android_Parcel_ReadableBlob {
        self.0 as *mut _
    }
}

unsafe impl AsNative<android_Parcel_WritableBlob> for WritableBlob<'_> {
    fn as_native(&self) -> *const android_Parcel_WritableBlob {
        self.0 as *const _
    }

    fn as_native_mut(&mut self) -> *mut android_Parcel_WritableBlob {
        self.0 as *mut _
    }
}

impl Blob for ReadableBlob<'_> {
    type Ptr = android_Parcel_ReadableBlob;

    fn from_ptr(blob: *mut Self::Ptr) -> Self {
        let blob_ref = unsafe { blob.as_mut() }.expect("Blob was a null pointer");
        ReadableBlob(blob_ref)
    }

    fn clear(&mut self) {
        unsafe { android_c_interface_Parcel_ReadableBlob_clear(self.0) }
    }

    fn release(&mut self) {
        unsafe { android_c_interface_Parcel_ReadableBlob_release(self.0) }
    }
}

impl Blob for WritableBlob<'_> {
    type Ptr = android_Parcel_WritableBlob;

    fn from_ptr(blob: *mut Self::Ptr) -> Self {
        let blob_ref = unsafe { blob.as_mut() }.expect("Blob was a null pointer");
        WritableBlob(blob_ref)
    }

    fn clear(&mut self) {
        unsafe { android_c_interface_Parcel_WritableBlob_clear(self.0) }
    }

    fn release(&mut self) {
        unsafe { android_c_interface_Parcel_WritableBlob_release(self.0) }
    }
}

impl ReadableBlob<'_> {
    pub fn data(&self) -> &[u8] {
        let mut data = unsafe { android_c_interface_Parcel_ReadableBlob_data(self.0) };
        let len = unsafe { android_c_interface_Parcel_ReadableBlob_size(self.0) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = NonNull::dangling().as_ptr();
        }

        unsafe { std::slice::from_raw_parts(data.cast(), len as usize) }
    }
}

impl WritableBlob<'_> {
    pub fn data(&mut self) -> &mut [u8] {
        let mut data = unsafe { android_c_interface_Parcel_WritableBlob_data(self.0) };
        let len = unsafe { android_c_interface_Parcel_WritableBlob_size(self.0) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = NonNull::dangling().as_ptr();
        }

        unsafe { std::slice::from_raw_parts_mut(data.cast(), len as usize) }
    }
}

impl Drop for ReadableBlob<'_> {
    fn drop(&mut self) {
        // This seems to just call release internally
        unsafe { android_c_interface_Parcel_ReadableBlob_Destructor(self.0) }
    }
}

impl Drop for WritableBlob<'_> {
    fn drop(&mut self) {
        // This seems to just call release internally
        unsafe { android_c_interface_Parcel_WritableBlob_Destructor(self.0) }
    }
}

#[test]
fn test_write_blob() {
    use super::Parcel;

    let mut parcel = Parcel::new();

    unsafe {
        assert!(parcel.set_data(b"Blob info here").is_ok());
    }

    assert_eq!(parcel.data(), b"Blob info here");
    assert_eq!(parcel.data_position(), 0);

    let mut writable_blob = parcel.write_blob(10, true).unwrap();

    // This starts 4 bytes into the parcel data because it is preceded by an
    // integer indicating it is in-place (BLOB_INPLACE = 0)
    assert_eq!(writable_blob.data(), b" info here");

    writable_blob.data()[2] = '-' as u8;

    assert_eq!(writable_blob.data(), b" i-fo here");

    drop(writable_blob);

    // Modifying the blob modifies the parcel (!) for small enough strings
    assert_eq!(parcel.data(), b"\0\0\0\0 i-fo here\0\0");
}
