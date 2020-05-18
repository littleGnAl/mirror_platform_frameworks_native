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
use crate::proxy::Interface;
use crate::sys::{libbinder_bindings::*, status_t};
use crate::utils::{AsNative, Str16};

use std::cmp::Ordering;
use std::convert::TryInto;
use std::ffi::{c_void, CStr};
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::ptr;
use std::slice;

mod blob;
mod file_descriptor;
mod parcelable;

use self::blob::Blob;
pub use self::blob::{ReadableBlob, WritableBlob};
pub use self::parcelable::{Deserialize, Serialize};
pub use self::file_descriptor::ParcelFileDescriptor;

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
        unsafe { &*(self as *const android_Parcel as *const Parcel) }
    }
}

impl AsMut<Parcel> for android_Parcel {
    fn as_mut(&mut self) -> &mut Parcel {
        unsafe { &mut *(self as *mut android_Parcel as *mut Parcel) }
    }
}

impl Parcel {
    /// Creates a new, empty `Parcel`.
    pub fn new() -> Self {
        let mut parcel = MaybeUninit::uninit();
        unsafe {
            android_Parcel_Parcel(parcel.as_mut_ptr());
            Self(parcel.assume_init())
        }
    }

    /// Crate a new `Parcel`, initialized with an RPC header for the given
    /// interface type.
    pub fn with_interface(interface: &Str16) -> Result<Self> {
        let mut parcel = Self::new();
        unsafe {
            binder_status(android_Parcel_writeInterfaceToken(
                parcel.as_native_mut(),
                interface.as_native(),
            ))?
        }
        Ok(parcel)
    }

    /// Parses the RPC header, returning true if the interface name in the
    /// header matches the expected interface from the caller.
    ///
    /// Additionally, enforceInterface does part of the work of propagating the
    /// StrictMode policy mask, populating the current IPCThreadState, which as
    /// an optimization may optionally be passed in.
    ///
    /// This method assumes the current data position is at the start of the RPC
    /// header, i.e. the start of the `Parcel`.
    pub fn enforce_interface<S: AsRef<Str16>>(&self, interface: &S) -> bool {
        unsafe {
            android_Parcel_enforceInterface(
                self.as_native(),
                interface.as_ref().as_native(),
                ptr::null_mut()
            )
        }
    }
}

// Data serialization methods
impl Parcel {
    /// Write a type that implements [`Serialize`] to the `Parcel`.
    pub fn write<S: Serialize+?Sized>(&mut self, parcelable: &S) -> Result<()> {
        parcelable.serialize(self)
    }

    /// Write a single byte to the `Parcel`.
    ///
    /// A single byte is written into a 32-bit word for compatibility with
    /// existing Parcel implementations.
    pub fn write_i8(&mut self, val: i8) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeByte(self.as_native_mut(), val)) }
    }

    /// Write a single byte to the `Parcel`.
    ///
    /// A single byte is written into a 32-bit word for compatibility with
    /// existing Parcel implementations.
    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeByte(self.as_native_mut(), val as i8)) }
    }

    /// Writes the length of a slice to the `Parcel`.
    ///
    /// This is used in AIDL-generated client side code to indicate the
    /// allocated space for an output array parameter.
    pub fn write_slice_size<T>(&mut self, slice: &[T]) -> Result<()> {
        let len: i32 = slice.len().try_into().or(Err(Error::BAD_VALUE))?;
        self.write(&len)
    }

    /// Write a [`File`] into the `Parcel`.
    ///
    /// The parcel takes ownership of the file and will handle closing the file
    /// when no longer needed.
    pub fn write_file(&mut self, file: File) -> Result<()> {
        unsafe { self.write_file_descriptor(file.into_raw_fd(), true) }
    }

    /// Create a writable blob stored in the `Parcel`.
    ///
    /// Set `mutable_copy` if the receiver of the parcel should receive a
    /// writable blob.
    ///
    /// If the blob is small it is stored in-place, otherwise it is transferred
    /// by way of an anonymous shared memory region. Prefer sending immutable
    /// blobs if possible since they may be subsequently transferred between
    /// processes without further copying whereas mutable blobs always need to
    /// be copied.
    pub fn write_blob<'b, 'p: 'b>(
        &'p mut self,
        len: size_t,
        mutable_copy: bool,
    ) -> Result<WritableBlob<'b>> {
        let mut blob = ptr::null_mut();
        let status = unsafe {
            android_c_interface_Parcel_writeBlob(self.as_native_mut(), len, mutable_copy, &mut blob)
        };

        binder_status(status).map(|_| WritableBlob::from_ptr(blob))
    }

    /// Write a successful status.
    ///
    /// This is like Parcel.java's writeNoException(). It simply writes a zero
    /// int32. Currently the native implementation doesn't do any of the
    /// StrictMode stack gathering and serialization that the Java
    /// implementation does.
    pub fn write_no_exception(&mut self) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeNoException(self.as_native_mut())) }
    }
}

// Data deserialization methods
impl Parcel {
    /// Attempt to read a type that implements [`Deserialize`] from this
    /// `Parcel`.
    pub fn read<D: Deserialize>(&self) -> Result<D> {
        D::deserialize(self)
    }

    /// Extract a slice of `len` bytes, starting at the current position in the
    /// Parcel. Returns an empty slice on errors (ie out of bounds).
    pub fn read_inplace(&self, len: size_t) -> &[u8] {
        unsafe {
            let data = android_Parcel_readInplace(self.as_native(), len);

            slice::from_raw_parts(as_nonnull_ptr(data as *const u8), len.try_into().unwrap())
        }
    }

    /// Read a single byte from the `Parcel`.
    ///
    /// Single bytes are stored as 32-bit words in parcels, so this method
    /// increments the data position by 4.
    pub fn read_i8(&self) -> Result<i8> {
        let mut byte = 0;
        let result = unsafe { android_Parcel_readByte1(self.as_native(), &mut byte) };

        binder_status(result).map(|_| byte)
    }

    /// Read a single byte from the `Parcel`.
    ///
    /// Single bytes are stored as 32-bit words in parcels, so this method
    /// increments the data position by 4.
    pub fn read_u8(&self) -> Result<u8> {
        self.read_i8().map(|b| b as u8)
    }

    /// Read a vector size from the `Parcel` and resize the given output vector
    /// to be correctly sized for that amount of data.
    ///
    /// This method is used in AIDL-generated server side code for methods that
    /// take a mutable slice reference parameter.
    pub fn resize_out_vec<D: Default + Deserialize>(&self, out_vec: &mut Vec<D>) -> Result<()> {
        let len: i32 = self.read()?;

        if len < 0 {
            return Err(Error::UNEXPECTED_NULL);
        }

        // usize in Rust may be 16-bit, so i32 may not fit
        let len = len.try_into().unwrap();
        out_vec.resize_with(len, Default::default);

        Ok(())
    }

    /// Read a vector size from the `Parcel` and either create a correctly sized
    /// vector for that amount of data or set the output parameter to None if
    /// the vector should be null.
    ///
    /// This method is used in AIDL-generated server side code for methods that
    /// take a mutable slice reference parameter.
    pub fn resize_nullable_out_vec<D: Default + Deserialize>(&self, out_vec: &mut Option<Vec<D>>) -> Result<()> {
        let len: i32 = self.read()?;

        if len < 0 {
            *out_vec = None;
        } else {
            // usize in Rust may be 16-bit, so i32 may not fit
            let len = len.try_into().unwrap();
            let mut vec = Vec::with_capacity(len);
            vec.resize_with(len, Default::default);
            *out_vec = Some(vec);
        }

        Ok(())
    }

    /// Read a UTF-16 encoded string and convert it to UTF-8
    pub fn read_utf8_from_utf16(&self) -> Result<String> {
        let u16_bytes = self.read_string16_inplace();

        String::from_utf16(u16_bytes).or(Err(Error::BAD_VALUE))
    }

    /// Read a C string from the `Parcel`.
    ///
    /// This method will read a raw C-style, null-terminated string from the
    /// parcel. This string should have been stored as a `CStr` in Rust, or via
    /// `Parcel::writeCString` in C++.
    pub fn read_c_string(&self) -> Option<&CStr> {
        let ptr = unsafe { android_Parcel_readCString(self.as_native()) };

        if ptr.is_null() {
            return None;
        }

        unsafe { Some(CStr::from_ptr(ptr)) }
    }

    /// Returns an in-place view of a UTF-16 string in this `Parcel`'s buffer.
    pub fn read_string16_inplace(&self) -> &[u16] {
        unsafe {
            let mut out_len = 0;
            let data = android_Parcel_readString16Inplace(self.as_native(), &mut out_len);
            slice::from_raw_parts(as_nonnull_ptr(data), out_len.try_into().unwrap())
        }
    }

    /// Read an exception code from the `Parcel`.
    ///
    /// Like Parcel.java's readExceptionCode(). Reads the first int32 off of a
    /// Parcel's header, returning 0 or the negative error code on exceptions,
    /// but also deals with skipping over rich response headers. Callers should
    /// use this to read & parse the response headers rather than doing it by
    /// hand.
    pub fn read_exception_code(&self) -> i32 {
        unsafe { android_Parcel_readExceptionCode(self.as_native()) }
    }

    /// Read a blob from the parcel.
    pub fn read_blob<'b, 'p: 'b>(&'p self, len: size_t) -> Result<ReadableBlob<'b>> {
        let mut blob = ptr::null_mut();
        let status = unsafe { android_c_interface_Parcel_readBlob(self.as_native(), len, &mut blob) };

        binder_status(status).map(|_| ReadableBlob::from_ptr(blob))
    }
}

// Internal APIs
impl Parcel {
    /// Returns the total amount of data contained in the parcel.
    pub(crate) fn data_size(&self) -> size_t {
        unsafe { android_Parcel_dataSize(self.as_native()) }
    }

    pub(crate) fn write_binder(&mut self, binder: &Interface) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_writeStrongBinder(
                self.as_native_mut(),
                binder.as_native(),
            ))
        }
    }

    pub(crate) unsafe fn read_binder(&self) -> Result<Option<Interface>> {
        let mut binder = ptr::null_mut();
        let status = android_c_interface_Parcel_readStrongBinder(self.as_native(), &mut binder);

        binder_status(status).map(|_| Interface::from_raw(binder))
    }

    /// Place a file descriptor into the parcel. The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    pub(crate) unsafe fn write_file_descriptor(&mut self, fd: RawFd, take_ownership: bool) -> Result<()> {
        binder_status(android_Parcel_writeFileDescriptor(
            self.as_native_mut(),
            fd,
            take_ownership,
        ))
    }

    /// Place a copy of a file descriptor into the parcel. A dup of the fd is made, which will
    /// be closed once the parcel is destroyed.
    pub(crate) unsafe fn write_dup_parcel_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupParcelFileDescriptor(
            self.as_native_mut(),
            fd,
        ))
    }

    /// Place a file descriptor into the parcel. A dup of the fd is made, which
    /// will be closed once the parcel is destroyed.
    pub(crate) unsafe fn write_dup_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupFileDescriptor(
            self.as_native_mut(),
            fd,
        ))
    }

    /// Retrieve a file descriptor from the parcel. This returns the raw fd
    /// in the parcel, which you do not own -- use dup() to get your own copy.
    pub(crate) unsafe fn read_file_descriptor(&self) -> Result<RawFd> {
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
    pub(crate) unsafe fn read_parcel_file_descriptor(&self) -> Result<RawFd> {
        let fd = android_Parcel_readParcelFileDescriptor(self.as_native());

        // Not using binder_status() as it only okays on 0 but other non negative fds may be valid
        // and currently the only error return is on BAD_TYPE.
        if fd == Error::BAD_TYPE as i32 {
            return Err(Error::BAD_TYPE);
        }

        Ok(fd)
    }
}

// APIs that are not (yet) exposed to Rust users, as we have not needed them
// yet. Some of these are used in internal tests.
#[allow(unused)]
impl Parcel {
    /// Get the raw bytes of this `Parcel`.
    pub(crate) fn data(&self) -> &[u8] {
        unsafe {
            let data = android_Parcel_data(self.as_native());
            slice::from_raw_parts(as_nonnull_ptr(data), self.data_size().try_into().unwrap())
        }
    }

    /// Returns the amount of data remaining to be read from the parcel. That is,
    /// data_size() - data_position().
    pub(crate) fn data_avail(&self) -> size_t {
        unsafe { android_Parcel_dataAvail(self.as_native()) }
    }

    /// Returns the total amount of space in the parcel. This is always >= dataSize().
    /// The difference between it and dataSize() is the amount of room left until the parcel
    /// needs to re-allocate its data buffer.
    pub(crate) fn data_capacity(&self) -> size_t {
        unsafe { android_Parcel_dataCapacity(self.as_native()) }
    }

    /// Returns the current position in the parcel data. Never more than data_size().
    pub(crate) fn data_position(&self) -> size_t {
        unsafe { android_Parcel_dataPosition(self.as_native()) }
    }

    /// Move the current read/write position in the parcel.
    pub(crate) fn set_data_position(&self, pos: size_t) -> Result<()> {
        // pos: New offset in the parcel; must be between 0 and data_size().
        if pos > self.data_size() {
            return Err(Error::BAD_VALUE);
        }

        unsafe {
            android_Parcel_setDataPosition(self.as_native(), pos);
        }

        Ok(())
    }

    pub(crate) fn free_data(&mut self) {
        unsafe { android_Parcel_freeData(self.as_native_mut()) }
    }

    pub(crate) fn objects_count(&self) -> size_t {
        unsafe { android_Parcel_objectsCount(self.as_native()) }
    }

    pub(crate) fn error_check(&self) -> status_t {
        unsafe { android_Parcel_errorCheck(self.as_native()) }
    }

    pub(crate) fn set_error(&mut self, err: status_t) {
        unsafe { android_Parcel_setError(self.as_native_mut(), err) }
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
    pub(crate) unsafe fn set_data_size(&mut self, size: size_t) -> Result<()> {
        let status = android_Parcel_setDataSize(self.as_native_mut(), size);

        binder_status(status)
    }

    /// Change the capacity (current available space) of the parcel.
    pub(crate) fn set_data_capacity(&mut self, size: size_t) -> Result<()> {
        // size: The new capacity of the parcel, in bytes. Can not be less than dataSize()
        // -- that is, you can not drop existing data with this method.
        if size < self.data_size() {
            return Err(Error::BAD_VALUE);
        }

        let status = unsafe { android_Parcel_setDataCapacity(self.as_native_mut(), size) };

        binder_status(status)
    }

    /// Unconditionally set the data payload of this `Parcel`.
    pub(crate) unsafe fn set_data(&mut self, data: &[u8]) -> Result<()> {
        let status = android_Parcel_setData(
            self.as_native_mut(),
            data.as_ptr(),
            data.len().try_into().unwrap(),
        );

        binder_status(status)
    }

    /// Read exactly enough elements of type `D` required to fill `slice`.
    // There is an implicit `Sized` bound on D, so you can't do something really
    // weird like D: [D2] here.
    pub(crate) fn read_to_slice<D: Deserialize>(&self, slice: &mut [D]) -> Result<()> {
        for item in slice.iter_mut() {
            *item = D::deserialize(self)?;
        }

        Ok(())
    }

    /// Read an i32 count, resize `vec` to that size, and attempt to fill it
    /// with count elements.
    pub(crate) fn read_to_vec<D: Default + Deserialize>(&self, vec: &mut Vec<D>) -> Result<()> {
        self.resize_out_vec(vec)?;
        self.read_to_slice::<D>(vec)
    }

    pub(crate) fn write_i32_slice(&mut self, array: &[i32]) -> Result<()> {
        let len = array.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeInt32Array(
                self.as_native_mut(),
                len,
                array.as_ptr(),
            ))
        }
    }

    /// The start offset and len are bounds checked by the original C++ code and
    /// return BAD_VALUE in such a case.
    pub(crate) fn append_from(
        &mut self,
        parcel: &Parcel,
        start: size_t,
        len: size_t,
    ) -> Result<()> {
        let status = unsafe {
            android_Parcel_appendFrom(self.as_native_mut(), parcel.as_native(), start, len)
        };

        binder_status(status)
    }

    pub(crate) fn allow_fds(&self) -> bool {
        unsafe { android_Parcel_allowFds(self.as_native()) }
    }

    pub(crate) fn push_allow_fds(&mut self, allow_fds: bool) -> bool {
        unsafe { android_Parcel_pushAllowFds(self.as_native_mut(), allow_fds) }
    }

    pub(crate) fn restore_allow_fds(&mut self, allow_fds: bool) {
        unsafe { android_Parcel_restoreAllowFds(self.as_native_mut(), allow_fds) }
    }

    pub(crate) fn has_file_descriptors(&self) -> bool {
        unsafe { android_Parcel_hasFileDescriptors(self.as_native()) }
    }

    pub(crate) fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_write(
                self.as_native_mut(),
                data.as_ptr() as *const c_void,
                data.len().try_into().unwrap(),
            ))
        }
    }

    pub(crate) fn write_unpadded(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_writeUnpadded(
                self.as_native_mut(),
                data.as_ptr() as *const c_void,
                data.len().try_into().unwrap(),
            ))
        }
    }

    /// Place a file descriptor into the parcel. The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    pub(crate) unsafe fn write_parcel_file_descriptor(
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

    /// Write an existing immutable blob file descriptor to the parcel.
    /// This allows the client to send the same blob to multiple processes
    /// as long as it keeps a dup of the blob file descriptor handy for later.
    pub(crate) unsafe fn write_dup_immutable_blob_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupImmutableBlobFileDescriptor(
            self.as_native_mut(),
            fd,
        ))
    }
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
        let ord = unsafe {
            android_Parcel_compareData(self.as_native() as *mut android_Parcel, other.as_native())
        };
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
    use crate::{String8, String16};

    let mut parcel = Parcel::new();

    assert_eq!(parcel.read::<bool>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i8(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<u16>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<i32>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<u32>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<i64>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<u64>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<f32>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<f64>(), Err(Error::NOT_ENOUGH_DATA));
    assert!(parcel.read_c_string().is_none());
    assert_eq!(parcel.read::<String8>(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read::<String16>(), Err(Error::UNEXPECTED_NULL));

    unsafe {
        assert_eq!(parcel.read_binder().err(), Some(Error::BAD_TYPE));
    }

    unsafe {
        parcel.set_data(b"Hello, Binder!\0").unwrap();
    }

    assert_eq!(parcel.read::<bool>().unwrap(), true);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i8().unwrap(), 72i8);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<u16>().unwrap(), 25928);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<i32>().unwrap(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<u32>().unwrap(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<i64>().unwrap(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<u64>().unwrap(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<f32>().unwrap(), 1143139100000000000000000000.0);
    assert_eq!(parcel.data_position(), 4);
    assert_eq!(parcel.read::<f32>().unwrap(), 40.043392);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read::<f64>().unwrap(), 34732488246.197815);
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

    assert!(parcel.write(&s).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let s: String8 = parcel.read().unwrap();

    assert_eq!(s.len(), 14);
    assert_eq!(s.as_str(), "Hello, Binder!");

    assert!(parcel.set_data_position(0).is_ok());
    assert_eq!(&parcel.data()[4..], b"Hello, Binder!\0\0");

    let s16 = String16::from("Hello, Binder!");

    assert!(parcel.write(&s16).is_ok());
    assert!(parcel.set_data_position(0).is_ok());
    assert_eq!(parcel.read::<String16>().unwrap(), s16);
}

#[test]
fn test_utf8_utf16_conversions() {
    let mut parcel = Parcel::new();

    assert!(parcel.write("Hello, Binder!").is_ok());
    assert!(parcel.set_data_position(0).is_ok());
    assert_eq!(parcel.read_utf8_from_utf16().unwrap(), "Hello, Binder!");
    assert!(parcel.set_data_position(0).is_ok());
    assert!(parcel
        .write(&["str1", "str2", "str3"][..])
        .is_ok());
    assert!(parcel
        .write(&[
            String::from("str4"),
            String::from("str5"),
            String::from("str6"),
        ][..])
        .is_ok());

    let s1 = "Hello, Binder!";
    let s2 = "This is a utf8 string.";
    let s3 = "Some more text here.";

    assert!(parcel.write(&[s1, s2, s3][..]).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.read::<Vec<String>>().unwrap(),
        ["str1", "str2", "str3"]
    );
    assert_eq!(
        parcel.read::<Vec<String>>().unwrap(),
        ["str4", "str5", "str6"]
    );
    assert_eq!(parcel.read::<Vec<String>>().unwrap(), [s1, s2, s3]);
}
