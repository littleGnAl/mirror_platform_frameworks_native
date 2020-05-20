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

//! Container for messages that are sent via binder.

use crate::error::{binder_status, Error, Result};
use crate::proxy::SpIBinder;
use crate::sys::{libbinder_bindings::*, status_t};
use crate::utils::{AsNative, Str16, Str8, String16, String8};
use crate::{Remotable, Binder};

use std::cmp::Ordering;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::mem::{self, size_of, MaybeUninit};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::ptr;
use std::slice;

use libc::{c_void, uid_t};

mod blob;
mod parcelable;

use self::blob::Blob;
pub use self::blob::{ReadableBlob, WritableBlob};
pub use self::parcelable::Parcelable;

/// Container for a message (data and object references) that can be sent
/// through Binder.
///
/// A Parcel can contain both flattened data that will be unflattened on the
/// other side of the IPC (using the various methods here for writing specific
/// types, or the general [`Parcelable`] trait), and references to live Binder
/// objects that will result in the other side receiving a proxy Binder
/// connected with the original Binder in the Parcel.
// Docs copied from /framworks/base/core/java/android/os/Parcel.java
//
// WARNING C++ Parcel is not POD, so cannot be passed by value across the FFI
// boundary. We must be careful that the bindgen generated struct is correctly
// sized and only passed by reference.
#[repr(transparent)]
pub struct Parcel(android_Parcel);

unsafe impl AsNative<android_Parcel> for Parcel {
    fn as_native(&self) -> *const android_Parcel {
        &self.0
    }

    fn as_native_mut(&mut self) -> *mut android_Parcel {
        &mut self.0
    }
}

/// Transform an arbitrary pointer into one which is non-null by mapping null
/// into a dangling pointer.
///
/// Rust docs explicitly state the slice data pointer cannot be null in
/// [`slice::from_raw_parts`], but can be dangling for 0 length slices.
fn as_nonnull_ptr<T>(ptr: *const T) -> *const T {
    if ptr.is_null() {
        ptr::NonNull::dangling().as_ptr()
    } else {
        ptr
    }
}

impl AsRef<Parcel> for android_Parcel {
    fn as_ref(&self) -> &Parcel {
        unsafe {
            &*(self as *const android_Parcel as *const Parcel)
        }
    }
}

impl AsMut<Parcel> for android_Parcel {
    fn as_mut(&mut self) -> &mut Parcel {
        unsafe {
            &mut *(self as *mut android_Parcel as *mut Parcel)
        }
    }
}

impl Parcel {
    /// Creates a new, empty `Parcel`.
    // This `Parcel` is owned, and will be destroyed when it is dropped.
    pub fn new() -> Self {
        let mut parcel = MaybeUninit::uninit();
        unsafe {
            android_Parcel_Parcel(parcel.as_mut_ptr());
            Self(parcel.assume_init())
        }
    }

    /// Get the raw bytes of this `Parcel`.
    pub fn data(&self) -> &[u8] {
        unsafe {
            let data = android_Parcel_data(self.as_native());
            slice::from_raw_parts(as_nonnull_ptr(data), self.data_size().try_into().unwrap())
        }
    }

    /// Returns the total amount of data contained in the parcel.
    pub fn data_size(&self) -> size_t {
        unsafe { android_Parcel_dataSize(self.as_native()) }
    }

    /// Returns the amount of data remaining to be read from the parcel. That is,
    /// data_size() - data_position().
    pub fn data_avail(&self) -> size_t {
        unsafe { android_Parcel_dataAvail(self.as_native()) }
    }

    /// Returns the current position in the parcel data. Never more than dataSize().
    pub fn data_position(&self) -> size_t {
        unsafe { android_Parcel_dataPosition(self.as_native()) }
    }

    /// Returns the total amount of space in the parcel. This is always >= dataSize().
    /// The difference between it and dataSize() is the amount of room left until the parcel
    /// needs to re-allocate its data buffer.
    pub fn data_capacity(&self) -> size_t {
        unsafe { android_Parcel_dataCapacity(self.as_native()) }
    }

    /// Change the amount of data in the parcel. Can be either smaller or larger than
    /// the current size. If larger than the current capacity, more memory will be allocated.
    ///
    /// # Safety
    ///
    /// Setting the size to be larger than it currently is, ie, going past the maximum size and
    /// into the capacity, or going past the capacity is a valid binder operation according to
    /// the above docs. However, this can cause uninit data to be referenced, which is *not*
    /// safe to do in Rust. IE calling the `data()` method after enlargening the size without
    /// first ensuring binder has overwritten the uninit data will very likely result in undefined
    /// behavior.
    ///
    /// Shrinking the `dataSize` into the original memory size is always a safe operation.
    pub unsafe fn set_data_size(&mut self, size: size_t) -> Result<()> {
        let status = android_Parcel_setDataSize(self.as_native_mut(), size);

        binder_status(status)
    }

    /// Move the current read/write position in the parcel.
    pub fn set_data_position(&self, pos: size_t) -> Result<()> {
        // pos: New offset in the parcel; must be between 0 and data_size().
        if pos > self.data_size() {
            return Err(Error::BAD_VALUE);
        }

        unsafe {
            android_Parcel_setDataPosition(self.as_native(), pos);
        }

        Ok(())
    }

    /// Change the capacity (current available space) of the parcel.
    pub fn set_data_capacity(&mut self, size: size_t) -> Result<()> {
        // size: The new capacity of the parcel, in bytes. Can not be less than dataSize()
        // -- that is, you can not drop existing data with this method.
        if size < self.data_size() {
            return Err(Error::BAD_VALUE);
        }

        let status = unsafe { android_Parcel_setDataCapacity(self.as_native_mut(), size) };

        binder_status(status)
    }

    /// Unconditionally set the data payload of this `Parcel`.
    pub unsafe fn set_data(&mut self, data: &[u8]) -> Result<()> {
        let status =
            android_Parcel_setData(self.as_native_mut(), data.as_ptr(), data.len().try_into().unwrap());

        binder_status(status)
    }

    /// The start offset and len are bounds checked by the original C++ code and
    /// return BAD_VALUE in such a case.
    pub fn append_from(&mut self, parcel: &Parcel, start: size_t, len: size_t) -> Result<()> {
        let status = unsafe { android_Parcel_appendFrom(self.as_native_mut(), parcel.as_native(), start, len) };

        binder_status(status)
    }

    pub fn allow_fds(&self) -> bool {
        unsafe { android_Parcel_allowFds(self.as_native()) }
    }

    pub fn push_allow_fds(&mut self, allow_fds: bool) -> bool {
        unsafe { android_Parcel_pushAllowFds(self.as_native_mut(), allow_fds) }
    }

    pub fn restore_allow_fds(&mut self, allow_fds: bool) {
        unsafe { android_Parcel_restoreAllowFds(self.as_native_mut(), allow_fds) }
    }

    pub fn has_file_descriptors(&self) -> bool {
        unsafe { android_Parcel_hasFileDescriptors(self.as_native()) }
    }

    /// Writes the RPC header.
    pub unsafe fn write_interface_token(&mut self, interface: &String16) -> Result<()> {
        binder_status(android_Parcel_writeInterfaceToken(
            self.as_native_mut(),
            interface.as_native(),
        ))
    }

    /// Parses the RPC header, returning true if the interface name
    /// in the header matches the expected interface from the caller.
    ///
    /// Additionally, enforceInterface does part of the work of
    /// propagating the StrictMode policy mask, populating the current
    /// IPCThreadState, which as an optimization may optionally be
    /// passed in.
    pub unsafe fn enforce_interface(&self, interface: &String16) -> bool {
        android_Parcel_enforceInterface(self.as_native(), interface.as_native(), ptr::null_mut())
    }

    pub fn free_data(&mut self) {
        unsafe { android_Parcel_freeData(self.as_native_mut()) }
    }

    pub fn objects_count(&self) -> size_t {
        unsafe { android_Parcel_objectsCount(self.as_native()) }
    }

    pub fn error_check(&self) -> status_t {
        unsafe { android_Parcel_errorCheck(self.as_native()) }
    }

    pub fn set_error(&mut self, err: status_t) {
        unsafe { android_Parcel_setError(self.as_native_mut(), err) }
    }

    pub unsafe fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        binder_status(android_Parcel_write(
            self.as_native_mut(),
            data.as_ptr() as *const c_void,
            data.len().try_into().unwrap(),
        ))
    }

    pub unsafe fn write_unpadded(&mut self, data: &[u8]) -> Result<()> {
        binder_status(android_Parcel_writeUnpadded(
            self.as_native_mut(),
            data.as_ptr() as *const c_void,
            data.len().try_into().unwrap(),
        ))
    }

    pub fn write_i32(&mut self, val: i32) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeInt32(self.as_native_mut(), val)) }
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeUint32(self.as_native_mut(), val)) }
    }

    pub fn write_i64(&mut self, val: i64) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeInt64(self.as_native_mut(), val)) }
    }

    pub fn write_u64(&mut self, val: u64) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeUint64(self.as_native_mut(), val)) }
    }

    pub fn write_f32(&mut self, val: f32) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeFloat(self.as_native_mut(), val)) }
    }

    pub fn write_f64(&mut self, val: f64) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeDouble(self.as_native_mut(), val)) }
    }

    pub unsafe fn write_c_string(&mut self, str: &CStr) -> Result<()> {
        binder_status(android_Parcel_writeCString(self.as_native_mut(), str.as_ptr()))
    }

    pub fn write_string8(&mut self, str: &Str8) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeString8(self.as_native_mut(), str.as_native())) }
    }

    pub fn write_string16(&mut self, str: &Str16) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeString16(self.as_native_mut(), str.as_native())) }
    }

    pub fn write_string16_bytes(&mut self, str: &[u16]) -> Result<()> {
        let status = unsafe {
            android_Parcel_writeString163(self.as_native_mut(), str.as_ptr(), str.len().try_into().unwrap())
        };

        binder_status(status)
    }

    pub fn write_service<T: Remotable>(&mut self, binder: &Binder<T>) -> Result<()> {
        binder.write_to_parcel(self)
    }

    pub(crate) fn write_binder(&mut self, binder: &SpIBinder) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_writeStrongBinder(
                self.as_native_mut(),
                binder.as_native(),
            ))
        }
    }

    pub fn write_i32_slice(&mut self, array: &[i32]) -> Result<()> {
        let len = array.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeInt32Array(
                self.as_native_mut(),
                len,
                array.as_ptr(),
            ))
        }
    }

    // There is an implicit `Sized` bound on P, so you can't do something really
    // weird like P: [P2] here and the `Copy` bound ensures only simple types
    // like ints and floats are byte copied.
    pub fn write_slice<P: Copy + Parcelable>(&mut self, slice: &[P]) -> Result<()> {
        let p_len: size_t = slice.len().try_into().unwrap();
        let byte_size = size_of::<P>()
            .try_into()
            .expect("Conversion to always succeed");
        let byte_len = p_len.checked_mul(byte_size).ok_or(Error::BAD_VALUE)?;

        // This is only safe to do for Copy types:
        unsafe {
            binder_status(android_Parcel_writeByteArray(
                self.as_native_mut(),
                byte_len,
                slice.as_ptr() as *const u8,
            ))
        }
    }

    pub fn write_u8_slice(&mut self, slice: &[u8]) -> Result<()> {
        let len = slice.len().try_into().unwrap();

        unsafe { binder_status(android_Parcel_writeByteArray(self.as_native_mut(), len, slice.as_ptr())) }
    }

    pub fn write_i8_slice(&mut self, slice: &[i8]) -> Result<()> {
        let len = slice.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeByteArray(
                self.as_native_mut(),
                len,
                slice.as_ptr() as *const u8,
            ))
        }
    }

    pub fn write_u16_slice(&mut self, slice: &[u16]) -> Result<()> {
        let len: size_t = slice.len().try_into().map_err(|_| Error::BAD_VALUE)?;
        let byte_len = len.checked_mul(2).ok_or(Error::BAD_VALUE)?;

        unsafe {
            binder_status(android_Parcel_writeByteArray(
                self.as_native_mut(),
                byte_len,
                slice.as_ptr() as *const u8,
            ))
        }
    }

    pub fn write_bool(&mut self, val: bool) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeBool(self.as_native_mut(), val)) }
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeChar(self.as_native_mut(), val)) }
    }

    pub fn write_i16(&mut self, val: i16) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeChar(self.as_native_mut(), val as u16)) }
    }

    pub fn write_i8(&mut self, val: i8) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeByte(self.as_native_mut(), val)) }
    }

    /// Take a UTF8 encoded string, convert to UTF16, write it to the parcel.
    pub fn write_utf8_as_utf16(&mut self, s: &str) -> Result<()> {
        self.write_string16(&*String16::from(s))
    }

    /// Takes multiple UTF8 encoded strings, convert to UTF16, write it to the parcel.
    pub fn write_utf8_slice_as_utf16<S: std::ops::Deref<Target = str>>(
        &mut self,
        slice: &[S],
    ) -> Result<()> {
        self.write_slice_size(slice)?;

        for str8 in slice {
            self.write_utf8_as_utf16(&*str8)?;
        }

        Ok(())
    }

    /// Writes the size of a slice to this `Parcel`. Similar to `Parcel::writeVectorSize` but
    /// usable on more types than just `Vec`s.
    pub fn write_slice_size<T>(&mut self, slice: &[T]) -> Result<()> {
        self.write_i32(slice.len().try_into().map_err(|_| Error::BAD_VALUE)?)
    }

    /// Place a file descriptor into the parcel. The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    // TODO: takeOwnership probably shouldn't be publicly exposed
    pub unsafe fn write_file_descriptor(&mut self, fd: RawFd, take_ownership: bool) -> Result<()> {
        binder_status(android_Parcel_writeFileDescriptor(
            self.as_native_mut(),
            fd,
            take_ownership,
        ))
    }

    /// Place a file descriptor into the parcel. A dup of the fd is made, which
    /// will be closed once the parcel is destroyed.
    pub unsafe fn write_dup_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupFileDescriptor(self.as_native_mut(), fd))
    }

    /// Place a file descriptor into the parcel. The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    // TODO: takeOwnership probably shouldn't be publicly exposed
    pub unsafe fn write_parcel_file_descriptor(
        &mut self,
        fd: RawFd,
        take_ownership: bool,
    ) -> Result<()> {
        binder_status(android_Parcel_writeParcelFileDescriptor(
            self.as_native_mut(),
            fd,
            take_ownership,
        ))
    }

    /// Place a copy of a file descriptor into the parcel. A dup of the fd is made, which will
    /// be closed once the parcel is destroyed.
    pub unsafe fn write_dup_parcel_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupParcelFileDescriptor(self.as_native_mut(), fd))
    }

    /// Place a [`File`] into the parcel. The file will be owned by the parcel
    /// and closed when the parcel is destroyed.
    pub fn write_file(&mut self, file: File) -> Result<()> {
        unsafe { self.write_file_descriptor(file.into_raw_fd(), true) }
    }

    /// Writes a blob to the parcel.
    ///
    /// If the blob is small, then it is stored in-place, otherwise it is
    /// transferred by way of an anonymous shared memory region. Prefer sending
    /// immutable blobs if possible since they may be subsequently transferred between
    /// processes without further copying whereas mutable blobs always need to be copied.
    pub fn write_blob<'b, 'p: 'b>(
        &'p mut self,
        len: size_t,
        mutable_copy: bool,
    ) -> Result<WritableBlob<'b>> {
        let mut blob = ptr::null_mut();
        let status =
            unsafe { android_c_interface_Parcel_writeBlob(self.as_native_mut(), len, mutable_copy, &mut blob) };

        binder_status(status).map(|_| WritableBlob::from_ptr(blob))
    }

    /// Write an existing immutable blob file descriptor to the parcel.
    /// This allows the client to send the same blob to multiple processes
    /// as long as it keeps a dup of the blob file descriptor handy for later.
    pub unsafe fn write_dup_immutable_blob_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupImmutableBlobFileDescriptor(
            self.as_native_mut(), fd,
        ))
    }

    /// Like Parcel.java's writeNoException(). Just writes a zero int32.
    /// Currently the native implementation doesn't do any of the StrictMode
    /// stack gathering and serialization that the Java implementation does.
    pub unsafe fn write_no_exception(&mut self) -> Result<()> {
        binder_status(android_Parcel_writeNoException(self.as_native_mut()))
    }

    /// Attempts to read any `Parcelable` type from this `Parcel`.
    pub fn read<P: Parcelable + ?Sized>(&self) -> Result<P::Deserialized> {
        P::deserialize(self)
    }

    /// Writes any `Parcelable` type to this `Parcel`.
    pub fn write<P: Parcelable>(&mut self, parcelable: &P) -> Result<()> {
        parcelable.serialize(self)
    }

    // There is an implicit `Sized` bound on P, so you can't do something really
    // weird like P: [P2] here and `Copy` ensures only simple types are byte
    // copied
    pub fn read_to_slice<P: Copy + Parcelable>(&self, slice: &mut [P]) -> Result<()> {
        let byte_size = size_of::<P>()
            .try_into()
            .expect("Conversion to always succeed");
        let len: size_t = slice.len().try_into().map_err(|_| Error::BAD_VALUE)?;
        let byte_len = len.checked_mul(byte_size).ok_or(Error::BAD_VALUE)?;
        let status = unsafe {
            android_Parcel_read(self.as_native(), slice.as_mut_ptr() as *mut libc::c_void, byte_len)
        };

        binder_status(status)
    }

    pub fn resize_vec<P: Default + Parcelable>(&self, vec: &mut Vec<P>) -> Result<()> {
        let byte_len: usize = self.read_i32()?.try_into().or(Err(Error::BAD_VALUE))?;
        let byte_size = size_of::<P>()
            .try_into()
            .expect("Conversion to always succeed");
        let new_len = byte_len.checked_div(byte_size).ok_or(Error::BAD_VALUE)?;

        vec.resize_with(new_len, Default::default);

        Ok(())
    }

    /// This method will read an i32 size, resize the vec to that size, and attempt to fill that buffer.
    /// This is the same approach that the C++ code uses to de/serialize arrays.
    pub fn read_to_vec<P: Copy + Default + Parcelable>(&self, vec: &mut Vec<P>) -> Result<()> {
        self.resize_vec(vec)?;
        self.read_to_slice::<P>(vec)
    }

    /// Attempts to read `len` number of bytes directly in the parser starting at the
    /// current position. Returns an empty slice on errors (ie attempted out of bounds).
    pub fn read_inplace(&self, len: size_t) -> &[u8] {
        unsafe {
            let data = android_Parcel_readInplace(self.as_native(), len);

            slice::from_raw_parts(as_nonnull_ptr(data as *const u8), len.try_into().unwrap())
        }
    }

    pub fn read_i32(&self) -> Result<i32> {
        let mut int32 = 0;
        let result = unsafe { android_Parcel_readInt321(self.as_native(), &mut int32) };

        binder_status(result).map(|_| int32)
    }

    pub fn read_u32(&self) -> Result<u32> {
        let mut uint32 = 0;
        let result = unsafe { android_Parcel_readUint321(self.as_native(), &mut uint32) };

        binder_status(result).map(|_| uint32)
    }

    pub fn read_i64(&self) -> Result<i64> {
        let mut int64 = 0;
        let result = unsafe { android_Parcel_readInt641(self.as_native(), &mut int64) };

        binder_status(result).map(|_| int64)
    }

    pub fn read_u64(&self) -> Result<u64> {
        let mut uint64 = 0;
        let result = unsafe { android_Parcel_readUint641(self.as_native(), &mut uint64) };

        binder_status(result).map(|_| uint64)
    }

    pub fn read_f32(&self) -> Result<f32> {
        let mut float = 0.;
        let result = unsafe { android_Parcel_readFloat1(self.as_native(), &mut float) };

        binder_status(result).map(|_| float)
    }

    pub fn read_f64(&self) -> Result<f64> {
        let mut double = 0.;
        let result = unsafe { android_Parcel_readDouble1(self.as_native(), &mut double) };

        binder_status(result).map(|_| double)
    }

    pub fn read_bool(&self) -> Result<bool> {
        // The C++ code creates the bool based on the value
        // being non-zero, so we shouldn't have to worry about
        // the bool being in an invalid state.
        let mut b = false;
        let result = unsafe { android_Parcel_readBool1(self.as_native(), &mut b) };

        binder_status(result).map(|_| b)
    }

    pub fn read_u16(&self) -> Result<u16> {
        let mut ch = 0;
        let result = unsafe { android_Parcel_readChar1(self.as_native(), &mut ch) };

        binder_status(result).map(|_| ch)
    }

    pub fn read_i16(&self) -> Result<i16> {
        let mut ch = 0u16;
        let result = unsafe { android_Parcel_readChar1(self.as_native(), &mut ch) };

        binder_status(result).map(|_| ch as i16)
    }

    pub fn read_i8(&self) -> Result<i8> {
        let mut byte = 0;
        let result = unsafe { android_Parcel_readByte1(self.as_native(), &mut byte) };

        binder_status(result).map(|_| byte)
    }

    /// Read a UTF16 encoded string, convert to UTF8
    pub fn read_utf8_from_utf16(&self) -> Result<String> {
        let u16_bytes = self.read_string16_inplace();

        String::from_utf16(u16_bytes).or(Err(Error::BAD_VALUE))
    }

    pub fn read_c_string(&self) -> Option<&CStr> {
        let ptr = unsafe { android_Parcel_readCString(self.as_native()) };

        if ptr.is_null() {
            return None;
        }

        unsafe { Some(CStr::from_ptr(ptr)) }
    }

    /// Attempt to read a `String8` from this `Parcel`.
    pub fn read_string8(&self) -> Result<String8> {
        let mut string = ptr::null_mut();
        let result = unsafe { android_c_interface_Parcel_readString8(self.as_native(), &mut string) };

        binder_status(result)?;

        if string.is_null() {
            // This should never happen, it means our interface code did not
            // allocate a new String8
            return Err(Error::NO_MEMORY);
        }

        let owned_str = unsafe { String8::from_raw(string) };
        Ok(owned_str)
    }

    /// Attempt to read a `String16` from this `Parcel`.
    pub fn read_string16(&self) -> Result<String16> {
        let mut s = MaybeUninit::uninit();
        let status = unsafe { android_c_interface_Parcel_readString16(self.as_native(), s.as_mut_ptr()) };

        binder_status(status).map(|_| unsafe { String16::from_raw(s.assume_init()) })
    }

    /// Returns a utf16 slice into this `Parcel`'s buffer inplace.
    pub fn read_string16_inplace(&self) -> &[u16] {
        unsafe {
            let mut out_len = 0;
            let data = android_Parcel_readString16Inplace(self.as_native(), &mut out_len);
            slice::from_raw_parts(as_nonnull_ptr(data), out_len.try_into().unwrap())
        }
    }

    pub(crate) unsafe fn read_strong_binder(&self) -> Result<Option<SpIBinder>> {
        let mut binder = ptr::null_mut();
        let status = android_c_interface_Parcel_readStrongBinder(self.as_native(), &mut binder);

        binder_status(status).map(|_| SpIBinder::from_raw(binder))
    }

    /// Reads utf16 string into a vec of utf8 strings.
    pub fn read_utf8_slice_from_utf16(&self) -> Result<Vec<String>> {
        let size = self.read_i32()?;
        let mut vec = Vec::with_capacity(size.try_into().unwrap());

        for _ in 0..size {
            vec.push(self.read_utf8_from_utf16()?);
        }

        Ok(vec)
    }

    /// Like Parcel.java's readExceptionCode(). Reads the first int32
    /// off of a Parcel's header, returning 0 or the negative error
    /// code on exceptions, but also deals with skipping over rich
    /// response headers. Callers should use this to read & parse the
    /// response headers rather than doing it by hand.
    pub fn read_exception_code(&self) -> i32 {
        unsafe { android_Parcel_readExceptionCode(self.as_native()) }
    }

    /// Retrieve a file descriptor from the parcel. This returns the raw fd
    /// in the parcel, which you do not own -- use dup() to get your own copy.
    pub unsafe fn read_file_descriptor(&self) -> Result<RawFd> {
        let fd = android_Parcel_readFileDescriptor(self.as_native());

        // Not using binder_status() as it only okays on 0 but other non negative fds may be valid
        // and currently the only error return is on BAD_TYPE.
        if fd == Error::BAD_TYPE as i32 {
            return Err(Error::BAD_TYPE);
        }

        Ok(fd)
    }

    /// Retrieve a file descriptor from the parcel. This returns the raw fd
    /// in the parcel, which you do not own -- use dup() to get your own copy.
    pub unsafe fn read_parcel_file_descriptor(&self) -> Result<RawFd> {
        let fd = android_Parcel_readParcelFileDescriptor(self.as_native());

        // Not using binder_status() as it only okays on 0 but other non negative fds may be valid
        // and currently the only error return is on BAD_TYPE.
        if fd == Error::BAD_TYPE as i32 {
            return Err(Error::BAD_TYPE);
        }

        Ok(fd)
    }

    /// Retrieve a [`File`] from the parcel.
    pub fn read_file(&self) -> Result<File> {
        unsafe {
            let fd = self.read_file_descriptor()?;
            // We don't actually own this, so we CANNOT drop it
            let file = File::from_raw_fd(fd);
            let file_dup = file.try_clone().map_err(|_| Error::BAD_VALUE);
            mem::forget(file);
            file_dup
        }
    }

    /// Reads a blob from the parcel.
    pub fn read_blob<'b, 'p: 'b>(&'p self, len: size_t) -> Result<ReadableBlob<'b>> {
        let mut blob = ptr::null_mut();
        let status = unsafe { android_c_interface_Parcel_readBlob(self.as_native(), len, &mut blob) };

        binder_status(status).map(|_| ReadableBlob::from_ptr(blob))
    }

    /// Explicitly close all file descriptors in the parcel.
    pub unsafe fn close_file_descriptors(&mut self) {
        android_Parcel_closeFileDescriptors(self.as_native_mut())
    }

    /// Debugging: get metric on current allocations.
    pub unsafe fn get_global_alloc_size() -> size_t {
        android_Parcel_getGlobalAllocSize()
    }

    /// Debugging: get metric on current allocations.
    pub unsafe fn get_global_alloc_count() -> size_t {
        android_Parcel_getGlobalAllocCount()
    }

    pub unsafe fn replace_calling_work_source_uid(&mut self, uid: uid_t) -> bool {
        android_Parcel_replaceCallingWorkSourceUid(self.as_native_mut(), uid)
    }

    /// Returns the work source provided by the caller. This can only be trusted for trusted calling
    /// uid.
    pub unsafe fn read_calling_work_source_uid(&self) -> uid_t {
        android_Parcel_readCallingWorkSourceUid(self.as_native())
    }

    /// There's also a `getBlobAshmemSize`, but it seems to return the same field
    /// as this method.
    pub fn get_open_ashmem_size(&self) -> size_t {
        unsafe { android_Parcel_getOpenAshmemSize(self.as_native()) }
    }

    // The following Parcel C++ methods are not yet exposed to Rust:
    //
    // void*               writeInplace(size_t len);
    // intptr_t            readIntPtr() const;
    // status_t            readIntPtr(intptr_t *pArg) const;
}

impl Drop for Parcel {
    fn drop(&mut self) {
        // Run the C++ Parcel complete object destructor
        unsafe { android_Parcel_Parcel_destructor(self.as_native_mut()) }
    }
}

impl PartialEq for Parcel {
    fn eq(&self, other: &Parcel) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Parcel {}

impl Ord for Parcel {
    fn cmp(&self, other: &Parcel) -> Ordering {
        let ord = unsafe { android_Parcel_compareData(self.as_native() as *mut android_Parcel, other.as_native()) };
        ord.cmp(&0)
    }
}

impl PartialOrd for Parcel {
    fn partial_cmp(&self, other: &Parcel) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
fn test_write_data() {
    let mut parcel = Parcel::new();

    assert_eq!(parcel.data(), []);
    assert_eq!(parcel.data_capacity(), 0);
    assert_eq!(parcel.data_avail(), 0);
    assert_eq!(parcel.data_position(), 0);

    unsafe {
        assert!(parcel.set_data(&[1, 2, 3, 4, 5]).is_ok());
    }

    assert_eq!(parcel.data(), [1, 2, 3, 4, 5]);
    assert_eq!(parcel.data_capacity(), 5);
    assert_eq!(parcel.data_avail(), 5);
    assert_eq!(parcel.data_position(), 0);

    unsafe {
        assert!(parcel.set_data_size(3).is_ok());
    }
    assert_eq!(parcel.data(), [1, 2, 3]);
    assert_eq!(parcel.data_capacity(), 5);
    assert_eq!(parcel.data_avail(), 3);
    assert_eq!(parcel.data_position(), 0);

    unsafe {
        assert!(parcel.set_data_size(4).is_ok());
    }
    assert_eq!(parcel.data(), [1, 2, 3, 4]);
    assert_eq!(parcel.data_capacity(), 5);
    assert_eq!(parcel.data_avail(), 4);
    assert_eq!(parcel.data_position(), 0);

    // Here we set the size greater than capacity, forcing allocation:
    unsafe {
        assert!(parcel.set_data_size(10).is_ok());
    }
    // This is filled with garbage bytes, so we can't safely call data()
    assert_eq!(parcel.data_size(), 10);
    unsafe {
        assert!(parcel.set_data_size(4).is_ok());
    }
    assert_eq!(parcel.data(), [1, 2, 3, 4]);

    let mut parcel2 = Parcel::new();

    unsafe {
        assert!(parcel2.set_data(&[1, 2, 3, 4, 5]).is_ok());
    }

    assert!(parcel2 > parcel);

    unsafe {
        assert!(parcel2.set_data_size(3).is_ok());
    }

    assert!(parcel2 < parcel);

    // Bounds checked
    assert_eq!(parcel2.append_from(&parcel, 11, 10), Err(Error::BAD_VALUE));
    assert_eq!(parcel2.data(), [1, 2, 3]);

    assert!(parcel2.set_data_position(3).is_ok());
    assert!(parcel2.append_from(&parcel, 1, 3).is_ok());
    assert_eq!(parcel2.data(), [1, 2, 3, 2, 3, 4]);

    parcel.free_data();

    assert_eq!(parcel.data(), []);
}

#[test]
fn test_file_descriptors() {
    let mut parcel = Parcel::new();

    assert!(parcel.allow_fds());
    assert!(!parcel.has_file_descriptors());

    parcel.push_allow_fds(false);

    assert!(!parcel.allow_fds());
    assert!(!parcel.has_file_descriptors());

    parcel.restore_allow_fds(true);

    assert!(parcel.allow_fds());
    assert!(!parcel.has_file_descriptors());
}

#[test]
fn test_read_data() {
    let mut parcel = Parcel::new();

    assert_eq!(parcel.read_bool(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i8(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u16(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i32(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u32(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i64(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u64(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_f32(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_f64(), Err(Error::NOT_ENOUGH_DATA));
    assert!(parcel.read_c_string().is_none());
    assert_eq!(parcel.read_string8(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_string16(), Err(Error::UNEXPECTED_NULL));

    unsafe {
        assert_eq!(parcel.read_strong_binder().err(), Some(Error::BAD_TYPE));
    }

    unsafe {
        parcel.set_data(b"Hello, Binder!\0").unwrap();
    }

    assert_eq!(parcel.read_bool().unwrap(), true);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i8().unwrap(), 72);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_u16().unwrap(), 25928);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i32().unwrap(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_u32().unwrap(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i64().unwrap(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_u64().unwrap(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_f32().unwrap(), 1143139100000000000000000000.0);
    assert_eq!(parcel.data_position(), 4);
    assert_eq!(parcel.read_f32().unwrap(), 40.043392);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_f64().unwrap(), 34732488246.197815);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.read_c_string().unwrap().to_bytes(),
        b"Hello, Binder!"
    );

    assert!(parcel.set_data_position(0).is_ok());

    // read/writeString uses a len field first which we didn't do in set_data above
    // and maybe some other metadata?
    let mut s = String8::new();

    s.append_bytes(b"Hello, Binder!").unwrap();

    assert!(parcel.write_string8(&s).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let s = parcel.read_string8().unwrap();

    assert_eq!(s.len(), 14);
    assert_eq!(s.as_str(), "Hello, Binder!");

    assert!(parcel.set_data_position(0).is_ok());
    assert_eq!(&parcel.data()[4..], b"Hello, Binder!\0\0");

    let s16 = String16::from("Hello, Binder!");

    assert!(parcel.write_string16(&s16).is_ok());
    assert!(parcel.set_data_position(0).is_ok());
    assert_eq!(parcel.read_string16().unwrap(), s16);
}

#[test]
fn test_utf8_utf16_conversions() {
    let mut parcel = Parcel::new();

    assert!(parcel.write_utf8_as_utf16("Hello, Binder!").is_ok());
    assert!(parcel.set_data_position(0).is_ok());
    assert_eq!(parcel.read_utf8_from_utf16().unwrap(), "Hello, Binder!");
    assert!(parcel.set_data_position(0).is_ok());
    assert!(parcel
        .write_utf8_slice_as_utf16(&["str1", "str2", "str3"])
        .is_ok());
    assert!(parcel
        .write_utf8_slice_as_utf16(&[
            String::from("str4"),
            String::from("str5"),
            String::from("str6"),
        ])
        .is_ok());

    let s1 = "Hello, Binder!";
    let s2 = "This is a utf8 string.";
    let s3 = "Some more text here.";

    assert!(parcel.write_utf8_slice_as_utf16(&[s1, s2, s3]).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.read_utf8_slice_from_utf16().unwrap(),
        ["str1", "str2", "str3"]
    );
    assert_eq!(
        parcel.read_utf8_slice_from_utf16().unwrap(),
        ["str4", "str5", "str6"]
    );
    assert_eq!(parcel.read_utf8_slice_from_utf16().unwrap(), [s1, s2, s3]);
}
