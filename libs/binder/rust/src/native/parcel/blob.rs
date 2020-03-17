use crate::native::libbinder_bindings::*;
use crate::native::parcel::Parcel;

use std::convert::TryInto;
use std::marker::PhantomData;

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
pub struct Blob<'r, K: BlobKind<'r>>(android_Parcel_Blob, PhantomData<K::Ref>);

impl<'r, K: BlobKind<'r>> Blob<'r, K> {
    pub(crate) fn new(blob: android_Parcel_Blob) -> Self {
        Blob(blob, PhantomData)
    }

    /// This method will just reset the blob fields and leak data.
    pub fn clear(&mut self) {
        unsafe { android_Parcel_Blob_clear(&mut self.0) }
    }

    /// This method will actually unmap the data, and then call `clear` internally.
    pub fn release(&mut self) {
        unsafe { android_Parcel_Blob_release(&mut self.0) }
    }
}

impl Blob<'_, Readable> {
    pub fn data(&self) -> &[u8] {
        let data = self.0.mData as *const u8;
        let len = self.0.mSize.try_into().unwrap();

        unsafe { std::slice::from_raw_parts(data, len) }
    }
}

impl Blob<'_, Writable> {
    pub fn data(&mut self) -> &mut [u8] {
        let data = self.0.mData as *mut u8;
        let len = self.0.mSize.try_into().unwrap();

        unsafe { std::slice::from_raw_parts_mut(data, len) }
    }
}

impl<'r, K: BlobKind<'r>> Drop for Blob<'r, K> {
    fn drop(&mut self) {
        // This seems to just call release internally
        unsafe { android_Parcel_Blob_Blob_destructor(&mut self.0) }
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
