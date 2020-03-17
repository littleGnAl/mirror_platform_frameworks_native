use crate::parcel::Parcel;
use crate::sys::libbinder_bindings::*;
use crate::utils::AsNative;

use std::convert::TryInto;
use std::marker::PhantomData;
use std::ptr::NonNull;

pub struct Writable;
pub struct Readable;

pub trait BlobKind<'r> {
    type Ref;

    // Must use the lifetime or else BlobKind errors as unconstrained.
    // This could be removed with GATs
    fn noop(&'r self) {}
}

impl<'r> BlobKind<'r> for Writable {
    type Ref = &'r mut ();
}

impl<'r> BlobKind<'r> for Readable {
    type Ref = &'r ();
}

// We enforce an im/mutable reference & lifetime through the type system so that
// Blob does not outlive its creator. This is because for small strings, the Blob
// will point into the Parcel's buffer and we want to handle that
// scenario even if it may own allocations of larger strings.
/// A read-only binary blob of data that can be read from a [`Parcel`]
///
/// A `ReadableBlob` is produced by the [`Parcel::read_blob`] method.
pub struct ReadableBlob<'a>(&'a mut android_Parcel_ReadableBlob);
/// A writable binary blob of data that will be sent in a [`Parcel`]
///
/// A `WritableBlob` is created by the [`Parcel::write_blob`] method.
pub struct WritableBlob<'a>(&'a mut android_Parcel_WritableBlob);

pub(super) trait Blob {
    type Ptr;

    fn from_ptr(blob: *mut Self::Ptr) -> Self;

    fn clear(&mut self);

    fn release(&mut self);
}

// impl<'r, K: BlobKind<'r>> Blob<'r, K> {
//     /// This method will just reset the blob fields and leak data.
//     pub fn clear(&mut self) {
//         unsafe { android_Parcel_Blob_clear(self.0) }
//     }

//     /// This method will actually unmap the data, and then call `clear` internally.
//     pub fn release(&mut self) {
//         unsafe { android_Parcel_Blob_release(self.0) }
//     }
// }

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
        unsafe { ReadableBlob(&mut *blob) }
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
        unsafe { WritableBlob(&mut *blob) }
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
    let mut parcel = Parcel::new();

    assert!(parcel.set_data(b"Blob info here").is_ok());

    assert_eq!(parcel.data(), b"Blob info here");
    assert_eq!(parcel.data_position(), 0);

    // This may be safe now
    let mut writable_blob = parcel.write_blob(10, true).unwrap();

    // REVIEW: Why does this start midway into the data?
    assert_eq!(writable_blob.data(), b" info here");

    writable_blob.data()[2] = '-' as u8;

    assert_eq!(writable_blob.data(), b" i-fo here");

    drop(writable_blob);

    // Modifying the blob modifies the parcel (!) for small enough strings
    // REVIEW: Why does data get zeroed out?
    assert_eq!(parcel.data(), b"\0\0\0\0 i-fo here\0\0");
}
