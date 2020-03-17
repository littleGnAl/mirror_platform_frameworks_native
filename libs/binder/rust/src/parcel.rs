//! Container for messages that are sent via binder.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use crate::error::{binder_status, Error, Result};
use crate::proxy::Interface;
use crate::sys::{libbinder_bindings::*, status_t};
use crate::utils::{AsNative, Sp, Str16, Str8, String16, String8, UniqueFd};
use crate::{Binder, Service};

use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::mem::{self, size_of, MaybeUninit};
use std::ops::Deref;
use std::os::unix::io::{FromRawFd, RawFd};
use std::ptr;
use std::slice;

use libc::{c_int, c_void, uid_t};

mod blob;
mod parcelable;

use self::blob::Blob;
pub use self::blob::{ReadableBlob, WritableBlob};
pub use self::parcelable::Parcelable;

/// Container for a message (data and object references) that can be sent through Binder.
///
/// A Parcel can contain both flattened data that will be unflattened on the
/// other side of the IPC (using the various methods here for writing specific
/// types, or the general [`Parcelable`] trait), and references to live Binder
/// objects that will result in the other side receiving a proxy Binder
/// connected with the original Binder in the Parcel.
// Docs copied from /framworks/base/core/java/android/os/Parcel.java
pub struct Parcel {
    ptr: *mut android_Parcel,
    owned: bool,
}

unsafe impl AsNative<android_Parcel> for Parcel {
    fn as_native(&self) -> *const android_Parcel {
        self.ptr
    }

    fn as_native_mut(&mut self) -> *mut android_Parcel {
        self.ptr
    }
}

impl Parcel {
    pub fn new() -> Self {
        let ptr = unsafe { android_c_interface_NewParcel() };
        Self { ptr, owned: true }
    }

    pub(crate) fn wrap(ptr: *mut android_Parcel) -> Self {
        Self { ptr, owned: false }
    }

    pub fn data(&self) -> &[u8] {
        let mut data = unsafe { android_Parcel_data(self.ptr) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = ptr::NonNull::dangling().as_ptr();
        }

        unsafe { slice::from_raw_parts(data, self.data_size().try_into().unwrap()) }
    }

    /// Returns the total amount of data contained in the parcel.
    pub fn data_size(&self) -> size_t {
        unsafe { android_Parcel_dataSize(self.ptr) }
    }

    /// Returns the amount of data remaining to be read from the parcel. That is,
    /// data_size() - data_position().
    pub fn data_avail(&self) -> size_t {
        unsafe { android_Parcel_dataAvail(self.ptr) }
    }

    /// Returns the current position in the parcel data. Never more than dataSize().
    pub fn data_position(&self) -> size_t {
        unsafe { android_Parcel_dataPosition(self.ptr) }
    }

    /// Returns the total amount of space in the parcel. This is always >= dataSize().
    /// The difference between it and dataSize() is the amount of room left until the parcel
    /// needs to re-allocate its data buffer.
    pub fn data_capacity(&self) -> size_t {
        unsafe { android_Parcel_dataCapacity(self.ptr) }
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
        let status = unsafe { android_Parcel_setDataSize(self.ptr, size) };

        binder_status(status)
    }

    /// Move the current read/write position in the parcel.
    pub fn set_data_position(&self, pos: size_t) -> Result<()> {
        // pos: New offset in the parcel; must be between 0 and data_size().
        if pos > self.data_size() {
            return Err(Error::BAD_VALUE);
        }

        unsafe {
            android_Parcel_setDataPosition(self.ptr, pos);
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

        let status = unsafe { android_Parcel_setDataCapacity(self.ptr, size) };

        binder_status(status)
    }

    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        let status = unsafe {
            android_Parcel_setData(self.ptr, data.as_ptr(), data.len().try_into().unwrap())
        };

        binder_status(status)
    }

    /// The start offset and len are bounds checked by the original C++ code and return BAD_VALUE in such a case.
    pub fn append_from(&mut self, parcel: &Parcel, start: size_t, len: size_t) -> Result<()> {
        let status = unsafe { android_Parcel_appendFrom(self.ptr, parcel.ptr, start, len) };

        binder_status(status)
    }

    pub fn compare_data(&mut self, other: &Parcel) -> c_int {
        unsafe { android_Parcel_compareData(self.ptr, other.ptr) }
    }

    pub fn allow_fds(&self) -> bool {
        unsafe { android_Parcel_allowFds(self.ptr) }
    }

    pub fn push_allow_fds(&mut self, allowFds: bool) -> bool {
        unsafe { android_Parcel_pushAllowFds(self.ptr, allowFds) }
    }

    pub fn restore_allow_fds(&mut self, allowFds: bool) {
        unsafe { android_Parcel_restoreAllowFds(self.ptr, allowFds) }
    }

    pub fn has_file_descriptors(&self) -> bool {
        unsafe { android_Parcel_hasFileDescriptors(self.ptr) }
    }

    /// Writes the RPC header.
    pub unsafe fn write_interface_token(&mut self, interface: &String16) -> Result<()> {
        binder_status(android_Parcel_writeInterfaceToken(
            self.ptr,
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
        android_Parcel_enforceInterface(self.ptr, interface.as_native(), ptr::null_mut())
    }

    // pub unsafe fn check_interface(&self, ibinder: &mut IBinder) -> bool {
    //     android_Parcel_checkInterface(self.ptr, ibinder.as_native_mut())
    // }

    pub fn free_data(&mut self) {
        unsafe { android_Parcel_freeData(self.ptr) }
    }

    pub fn objects_count(&self) -> size_t {
        unsafe { android_Parcel_objectsCount(self.ptr) }
    }

    pub fn error_check(&self) -> status_t {
        unsafe { android_Parcel_errorCheck(self.ptr) }
    }

    pub fn set_error(&mut self, err: status_t) {
        unsafe { android_Parcel_setError(self.ptr, err) }
    }

    pub unsafe fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        binder_status(android_Parcel_write(
            self.ptr,
            data.as_ptr() as *const c_void,
            data.len().try_into().unwrap(),
        ))
    }

    // void*               writeInplace(size_t len);

    pub unsafe fn write_unpadded(&mut self, data: &[u8]) -> Result<()> {
        binder_status(android_Parcel_writeUnpadded(
            self.ptr,
            data.as_ptr() as *const c_void,
            data.len().try_into().unwrap(),
        ))
    }

    pub fn write_i32(&mut self, val: i32) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeInt32(self.ptr, val)) }
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeUint32(self.ptr, val)) }
    }

    pub fn write_i64(&mut self, val: i64) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeInt64(self.ptr, val)) }
    }

    pub fn write_u64(&mut self, val: u64) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeUint64(self.ptr, val)) }
    }

    pub fn write_f32(&mut self, val: f32) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeFloat(self.ptr, val)) }
    }

    pub fn write_f64(&mut self, val: f64) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeDouble(self.ptr, val)) }
    }

    pub unsafe fn write_c_string(&mut self, str: &CStr) -> Result<()> {
        binder_status(android_Parcel_writeCString(self.ptr, str.as_ptr()))
    }

    pub fn write_string8(&mut self, str: &Str8) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeString8(self.ptr, str.as_native())) }
    }

    pub fn write_string16(&mut self, str: &Str16) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeString16(self.ptr, str.as_native())) }
    }

    pub fn write_string16_bytes(&mut self, str: &[u16]) -> Result<()> {
        let status = unsafe {
            android_Parcel_writeString163(self.ptr, str.as_ptr(), str.len().try_into().unwrap())
        };

        binder_status(status)
    }

    // status_t            writeStrongBinder(const sp<IBinder>& val);

    pub fn write_binder_native<T: Binder>(&mut self, binder: &Service<T>) -> Result<()> {
        binder.write_to_parcel(self)
    }

    pub(crate) fn write_binder(&mut self, binder: &Interface) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_writeStrongBinder(
                self.ptr,
                binder.as_native(),
            ))
        }
    }

    pub fn write_i32_slice(&mut self, array: &[i32]) -> Result<()> {
        let len = array.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeInt32Array(
                self.ptr,
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
                self.ptr,
                byte_len,
                slice.as_ptr() as *const u8,
            ))
        }
    }

    pub fn write_u8_slice(&mut self, slice: &[u8]) -> Result<()> {
        let len = slice.len().try_into().unwrap();

        unsafe { binder_status(android_Parcel_writeByteArray(self.ptr, len, slice.as_ptr())) }
    }

    pub fn write_i8_slice(&mut self, slice: &[i8]) -> Result<()> {
        let len = slice.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeByteArray(
                self.ptr,
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
                self.ptr,
                byte_len,
                slice.as_ptr() as *const u8,
            ))
        }
    }

    pub fn write_bool(&mut self, val: bool) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeBool(self.ptr, val)) }
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeChar(self.ptr, val)) }
    }

    pub fn write_i16(&mut self, val: i16) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeChar(self.ptr, val as u16)) }
    }

    pub fn write_i8(&mut self, val: i8) -> Result<()> {
        unsafe { binder_status(android_Parcel_writeByte(self.ptr, val)) }
    }

    /// Take a UTF8 encoded string, convert to UTF16, write it to the parcel.
    pub fn write_utf8_as_utf16(&mut self, s: &str) -> Result<()> {
        self.write_string16(&*String16::from(s))
    }

    /// Takes multiple UTF8 encoded strings, convert to UTF16, write it to the parcel.
    // pub fn write_utf8_slice_as_utf16<S: Deref<Target=str>>(&mut self, slice: &[S]) -> Result<()> {
    //     self.write_slice_size(slice)?;

    //     for str8 in slice {
    //         self.write_utf8_as_utf16(&*str8)?;
    //     }

    //     Ok(())
    // }

    // status_t            writeStrongBinderVector(const std::optional<std::vector<sp<IBinder>>>& val);
    // status_t            writeStrongBinderVector(const std::unique_ptr<std::vector<sp<IBinder>>>& val);
    // status_t            writeStrongBinderVector(const std::vector<sp<IBinder>>& val);

    // Write an Enum vector with underlying type int8_t.
    // Does not use padding; each byte is contiguous.
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            writeEnumVector(const std::vector<T>& val);
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            writeEnumVector(const std::optional<std::vector<T>>& val);
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            writeEnumVector(const std::unique_ptr<std::vector<T>>& val);
    // Write an Enum vector with underlying type != int8_t.
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            writeEnumVector(const std::vector<T>& val);
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            writeEnumVector(const std::optional<std::vector<T>>& val);
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            writeEnumVector(const std::unique_ptr<std::vector<T>>& val);
    // template<typename T>
    // status_t            writeNullableParcelable(const std::optional<T>& parcelable);
    // template<typename T>
    // status_t            writeNullableParcelable(const std::unique_ptr<T>& parcelable);
    // template<typename T>
    // status_t            write(const Flattenable<T>& val);
    // template<typename T>
    // status_t            write(const LightFlattenable<T>& val);

    /// Writes the size of a slice to this `Parcel`. Similar to `Parcel::writeVectorSize` but
    /// usable on more types than just `Vec`s.
    pub fn write_slice_size<T>(&mut self, slice: &[T]) -> Result<()> {
        self.write_i32(slice.len().try_into().map_err(|_| Error::BAD_VALUE)?)
    }

    /// Place a native_handle into the parcel (the native_handle's file-
    /// descriptors are dup'ed, so it is safe to delete the native_handle
    /// when this function returns).
    // pub unsafe fn write_native_handle(&mut self, handle: &NativeHandle) -> Result<()> {
    //     binder_status(android_Parcel_writeNativeHandle(self.ptr, handle.0))
    // }

    /// Place a file descriptor into the parcel. The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    // TODO: takeOwnership probably shouldn't be publicly exposed
    pub unsafe fn write_file_descriptor(&mut self, fd: RawFd, takeOwnership: bool) -> Result<()> {
        binder_status(android_Parcel_writeFileDescriptor(
            self.ptr,
            fd,
            takeOwnership,
        ))
    }

    /// Place a file descriptor into the parcel. A dup of the fd is made, which
    /// will be closed once the parcel is destroyed.
    pub unsafe fn write_dup_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupFileDescriptor(self.ptr, fd))
    }

    /// Place a file descriptor into the parcel. The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    // TODO: takeOwnership probably shouldn't be publicly exposed
    pub unsafe fn write_parcel_file_descriptor(
        &mut self,
        fd: RawFd,
        takeOwnership: bool,
    ) -> Result<()> {
        binder_status(android_Parcel_writeParcelFileDescriptor(
            self.ptr,
            fd,
            takeOwnership,
        ))
    }

    /// Place a copy of a file descriptor into the parcel. A dup of the fd is made, which will
    /// be closed once the parcel is destroyed.
    pub unsafe fn write_dup_parcel_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupParcelFileDescriptor(self.ptr, fd))
    }

    /// Place a file descriptor into the parcel. This will not affect the
    /// semantics of the smart file descriptor. A new descriptor will be
    /// created, and will be closed when the parcel is destroyed.
    // REVIEW: Should this take a reference since a new fd is created?
    pub unsafe fn write_unique_file_descriptor(&mut self, fd: UniqueFd) -> Result<()> {
        binder_status(android_Parcel_writeUniqueFileDescriptor(self.ptr, fd.0))
    }

    // Place a vector of file desciptors into the parcel. Each descriptor is
    // dup'd as in writeDupFileDescriptor
    // status_t            writeUniqueFileDescriptorVector(
    //                         const std::optional<std::vector<base::unique_fd>>& val);
    // status_t            writeUniqueFileDescriptorVector(
    //                         const std::unique_ptr<std::vector<base::unique_fd>>& val);
    // status_t            writeUniqueFileDescriptorVector(
    //                         const std::vector<base::unique_fd>& val);

    /// Writes a blob to the parcel.
    ///
    /// If the blob is small, then it is stored in-place, otherwise it is
    /// transferred by way of an anonymous shared memory region. Prefer sending
    /// immutable blobs if possible since they may be subsequently transferred between
    /// processes without further copying whereas mutable blobs always need to be copied.
    // REVIEW: mutableCopy maybe shouldn't be part of the public API?
    // It's not currently clear whether or not we can make this fully safe.
    pub fn write_blob<'b, 'p: 'b>(
        &'p mut self,
        len: size_t,
        mutableCopy: bool,
    ) -> Result<WritableBlob<'b>> {
        let mut blob = ptr::null_mut();
        let status =
            unsafe { android_c_interface_Parcel_writeBlob(self.ptr, len, mutableCopy, &mut blob) };

        binder_status(status).map(|_| WritableBlob::from_ptr(blob))
    }

    /// Write an existing immutable blob file descriptor to the parcel.
    /// This allows the client to send the same blob to multiple processes
    /// as long as it keeps a dup of the blob file descriptor handy for later.
    pub unsafe fn write_dup_immutable_blob_file_descriptor(&mut self, fd: RawFd) -> Result<()> {
        binder_status(android_Parcel_writeDupImmutableBlobFileDescriptor(
            self.ptr, fd,
        ))
    }

    // status_t            writeObject(const flat_binder_object& val, bool nullMetaData);

    /// Like Parcel.java's writeNoException(). Just writes a zero int32.
    /// Currently the native implementation doesn't do any of the StrictMode
    /// stack gathering and serialization that the Java implementation does.
    pub unsafe fn write_no_exception(&mut self) -> Result<()> {
        binder_status(android_Parcel_writeNoException(self.ptr))
    }

    /// Reads any `Parcelable` type from this `Parcel`. Panics on failure to parse.
    pub fn read<P: Parcelable + ?Sized>(&self) -> P::Deserialized {
        P::deserialize(self).unwrap()
    }

    /// Attempts to read any `Parcelable` type from this `Parcel`.
    pub fn try_read<P: Parcelable + ?Sized>(&self) -> Result<P::Deserialized> {
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
            android_Parcel_read(self.ptr, slice.as_mut_ptr() as *mut libc::c_void, byte_len)
        };

        binder_status(status)
    }

    pub fn resize_vec<P: Default + Parcelable>(&self, vec: &mut Vec<P>) -> Result<()> {
        let byte_len: usize = self
            .try_read_i32()?
            .try_into()
            .expect("Conversion to always succeed");
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
        let mut data = unsafe { android_Parcel_readInplace(self.ptr, len) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = ptr::NonNull::dangling().as_ptr();
        }

        unsafe { slice::from_raw_parts(data as *const u8, len.try_into().unwrap()) }
    }

    pub fn read_i32(&self) -> i32 {
        unsafe { android_Parcel_readInt32(self.ptr) }
    }

    pub fn try_read_i32(&self) -> Result<i32> {
        let mut int32 = 0;
        let result = unsafe { android_Parcel_readInt321(self.ptr, &mut int32) };

        binder_status(result).map(|_| int32)
    }

    pub fn read_u32(&self) -> u32 {
        unsafe { android_Parcel_readUint32(self.ptr) }
    }

    pub fn try_read_u32(&self) -> Result<u32> {
        let mut uint32 = 0;
        let result = unsafe { android_Parcel_readUint321(self.ptr, &mut uint32) };

        binder_status(result).map(|_| uint32)
    }

    pub fn read_i64(&self) -> i64 {
        unsafe { android_Parcel_readInt64(self.ptr) }
    }

    pub fn try_read_i64(&self) -> Result<i64> {
        let mut int64 = 0;
        let result = unsafe { android_Parcel_readInt641(self.ptr, &mut int64) };

        binder_status(result).map(|_| int64)
    }

    pub fn read_u64(&self) -> u64 {
        unsafe { android_Parcel_readUint64(self.ptr) }
    }

    pub fn try_read_u64(&self) -> Result<u64> {
        let mut uint64 = 0;
        let result = unsafe { android_Parcel_readUint641(self.ptr, &mut uint64) };

        binder_status(result).map(|_| uint64)
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn read_f32(&self) -> f32 {
        unsafe { android_Parcel_readFloat(self.ptr) }
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn try_read_f32(&self) -> Result<f32> {
        let mut float = 0.;
        let result = unsafe { android_Parcel_readFloat1(self.ptr, &mut float) };

        binder_status(result).map(|_| float)
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn read_f64(&self) -> f64 {
        unsafe { android_Parcel_readDouble(self.ptr) }
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn try_read_f64(&self) -> Result<f64> {
        let mut double = 0.;
        let result = unsafe { android_Parcel_readDouble1(self.ptr, &mut double) };

        binder_status(result).map(|_| double)
    }

    // REVIEW: We probably don't want to just hand out rawptrs?:
    // intptr_t            readIntPtr() const;
    // status_t            readIntPtr(intptr_t *pArg) const;

    pub fn read_bool(&self) -> bool {
        // The C++ code creates the bool based on the value
        // being non-zero, so we shouldn't have to worry about
        // the bool being in an invalid state.
        unsafe { android_Parcel_readBool(self.ptr) }
    }

    pub fn try_read_bool(&self) -> Result<bool> {
        // The C++ code creates the bool based on the value
        // being non-zero, so we shouldn't have to worry about
        // the bool being in an invalid state.
        let mut b = false;
        let result = unsafe { android_Parcel_readBool1(self.ptr, &mut b) };

        binder_status(result).map(|_| b)
    }

    pub fn read_u16(&self) -> u16 {
        unsafe { android_Parcel_readChar(self.ptr) }
    }

    pub fn try_read_u16(&self) -> Result<u16> {
        let mut ch = 0;
        let result = unsafe { android_Parcel_readChar1(self.ptr, &mut ch) };

        binder_status(result).map(|_| ch)
    }

    pub fn read_i16(&self) -> i16 {
        unsafe { android_Parcel_readChar(self.ptr) as i16 }
    }

    pub fn try_read_i16(&self) -> Result<i16> {
        let mut ch = 0u16;
        let result = unsafe { android_Parcel_readChar1(self.ptr, &mut ch) };

        binder_status(result).map(|_| ch as i16)
    }

    pub fn read_i8(&self) -> i8 {
        unsafe { android_Parcel_readByte(self.ptr) }
    }

    pub fn try_read_i8(&self) -> Result<i8> {
        let mut byte = 0;
        let result = unsafe { android_Parcel_readByte1(self.ptr, &mut byte) };

        binder_status(result).map(|_| byte)
    }

    /// Read a UTF16 encoded string, convert to UTF8
    // pub fn read_utf8_from_utf16(&self) -> String8 {
    //     let u16_bytes = self.read_string16_inplace();

    //     if u16_bytes.is_empty() {
    //         return String8::new()
    //     }

    //     u16_bytes.into()
    // }

    pub fn read_c_string(&self) -> Option<&CStr> {
        let ptr = unsafe { android_Parcel_readCString(self.ptr) };

        if ptr.is_null() {
            return None;
        }

        unsafe { Some(CStr::from_ptr(ptr)) }
    }

    /// Reads a `String8` from this `Parcel` or return an empty `String8` on error.
    pub fn read_string8(&self) -> String8 {
        self.try_read_string8().unwrap_or(String8::new())
    }

    /// Attempt to read a `String8` from this `Parcel`.
    pub fn try_read_string8(&self) -> Result<String8> {
        let mut string = ptr::null_mut();
        let result = unsafe { android_c_interface_Parcel_readString8(self.ptr, &mut string) };

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
    pub fn try_read_string16(&self) -> Result<String16> {
        let mut s = MaybeUninit::uninit();
        let status = unsafe { android_c_interface_Parcel_readString16(self.ptr, s.as_mut_ptr()) };

        binder_status(status).map(|_| unsafe { String16::from_raw(s.assume_init()) })
    }

    /// Reads a `String16` from this `Parcel` or return an empty `String16` on error.
    pub fn read_string16(&self) -> String16 {
        self.try_read_string16().unwrap_or(String16::new())
    }

    /// Returns a utf16 slice into this `Parcel`'s buffer inplace.
    pub fn read_string16_inplace(&self) -> &[u16] {
        let mut out_len = 0;
        let mut data = unsafe { android_Parcel_readString16Inplace(self.ptr, &mut out_len) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = ptr::NonNull::dangling().as_ptr();
        }

        unsafe { slice::from_raw_parts(data, out_len.try_into().unwrap()) }
    }

    pub(crate) unsafe fn read_strong_binder(&self) -> Interface {
        self.try_read_strong_binder().unwrap().unwrap()
    }

    pub(crate) unsafe fn try_read_strong_binder(&self) -> Result<Option<Interface>> {
        let mut binder = ptr::null_mut();
        let status = android_c_interface_Parcel_readStrongBinder(self.ptr, &mut binder);

        binder_status(status).map(|_| Interface::from_raw(binder))
    }

    // status_t            readNullableStrongBinder(sp<IBinder>* val) const;

    // Read an Enum vector with underlying type int8_t.
    // Does not use padding; each byte is contiguous.
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            readEnumVector(std::vector<T>* val) const;
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            readEnumVector(std::unique_ptr<std::vector<T>>* val) const;
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            readEnumVector(std::optional<std::vector<T>>* val) const;
    // Read an Enum vector with underlying type != int8_t.
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            readEnumVector(std::vector<T>* val) const;
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            readEnumVector(std::unique_ptr<std::vector<T>>* val) const;
    // template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    // status_t            readEnumVector(std::optional<std::vector<T>>* val) const;
    // template<typename T>
    // status_t            readNullableStrongBinder(sp<T>* val) const;
    // status_t            readStrongBinderVector(std::optional<std::vector<sp<IBinder>>>* val) const;
    // status_t            readStrongBinderVector(std::unique_ptr<std::vector<sp<IBinder>>>* val) const;
    // status_t            readStrongBinderVector(std::vector<sp<IBinder>>* val) const;

    /// Reads utf16 string into a vec of utf8 strings.
    // pub fn read_utf8_slice_from_utf16(&self) -> Result<Vec<String8>> {
    //     let size = self.try_read_i32()?;
    //     let mut vec = Vec::with_capacity(size.try_into().unwrap());

    //     for _ in 0..size {
    //         vec.push(self.read_utf8_from_utf16());
    //     }

    //     Ok(vec)
    // }

    // template<typename T>
    // status_t            read(Flattenable<T>& val) const;
    // template<typename T>
    // status_t            read(LightFlattenable<T>& val) const;

    /// Like Parcel.java's readExceptionCode(). Reads the first int32
    /// off of a Parcel's header, returning 0 or the negative error
    /// code on exceptions, but also deals with skipping over rich
    /// response headers. Callers should use this to read & parse the
    /// response headers rather than doing it by hand.
    pub fn read_exception_code(&self) -> i32 {
        unsafe { android_Parcel_readExceptionCode(self.ptr) }
    }

    /// Retrieve native_handle from the parcel. This returns a copy of the
    /// parcel's native_handle (the caller takes ownership). The caller
    /// must free the native_handle with native_handle_close() and
    /// native_handle_delete().
    // pub unsafe fn read_native_handle(&self) -> NativeHandle {
    //     NativeHandle(android_Parcel_readNativeHandle(self.ptr))
    // }

    /// Retrieve a file descriptor from the parcel. This returns the raw fd
    /// in the parcel, which you do not own -- use dup() to get your own copy.
    pub unsafe fn read_file_descriptor(&self) -> Result<RawFd> {
        let fd = android_Parcel_readFileDescriptor(self.ptr);

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
        let fd = android_Parcel_readParcelFileDescriptor(self.ptr);

        // Not using binder_status() as it only okays on 0 but other non negative fds may be valid
        // and currently the only error return is on BAD_TYPE.
        if fd == Error::BAD_TYPE as i32 {
            return Err(Error::BAD_TYPE);
        }

        Ok(fd)
    }

    /// Retrieve a smart file descriptor from the parcel.
    pub unsafe fn read_unique_file_descriptor(&self) -> Result<UniqueFd> {
        let mut fd = UniqueFd::new();
        let status = android_Parcel_readUniqueFileDescriptor(self.ptr, fd.0);

        binder_status(status)?;

        Ok(fd)
    }

    /// Retrieve a [`UniqueFd`] smart file descriptor from the parcel.
    pub unsafe fn read_unique_parcel_file_descriptor(&self) -> Result<UniqueFd> {
        let mut fd = UniqueFd::new();
        let status = android_Parcel_readUniqueParcelFileDescriptor(self.ptr, fd.0);

        binder_status(status)?;

        Ok(fd)
    }

    // Retrieve a vector of smart file descriptors from the parcel.
    // status_t            readUniqueFileDescriptorVector(
    //                         std::optional<std::vector<base::unique_fd>>* val) const;
    // status_t            readUniqueFileDescriptorVector(
    //                         std::unique_ptr<std::vector<base::unique_fd>>* val) const;
    // status_t            readUniqueFileDescriptorVector(
    //                         std::vector<base::unique_fd>* val) const;

    /// Reads a blob from the parcel.
    // REVIEW: It's not currently clear whether or not we can make this fully safe.
    pub fn read_blob<'b, 'p: 'b>(&self, len: size_t) -> Result<ReadableBlob<'b>> {
        let mut blob = ptr::null_mut();
        let status = unsafe { android_c_interface_Parcel_readBlob(self.ptr, len, &mut blob) };

        binder_status(status).map(|_| ReadableBlob::from_ptr(blob))
    }

    // const flat_binder_object* readObject(bool nullMetaData) const;

    /// Explicitly close all file descriptors in the parcel.
    pub unsafe fn close_file_descriptors(&mut self) {
        android_Parcel_closeFileDescriptors(self.ptr)
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
        android_Parcel_replaceCallingWorkSourceUid(self.ptr, uid)
    }

    /// Returns the work source provided by the caller. This can only be trusted for trusted calling
    /// uid.
    pub unsafe fn read_calling_work_source_uid(&self) -> uid_t {
        android_Parcel_readCallingWorkSourceUid(self.ptr)
    }

    /// There's also a `getBlobAshmemSize`, but it seems to return the same field
    /// as this method.
    pub fn get_open_ashmem_size(&self) -> size_t {
        unsafe { android_Parcel_getOpenAshmemSize(self.ptr) }
    }
}

impl Drop for Parcel {
    fn drop(&mut self) {
        if (self.owned) {
            // Run the C++ Parcel complete object destructor
            unsafe { android_Parcel_Parcel_destructor(self.ptr) }
        }
        // If we don't own this pointer, then we should let C++ destroy it for
        // us.
    }
}

// // TODO: Move to better location?
// pub struct NativeHandle(*mut native_handle);

// impl Drop for NativeHandle {
//     fn drop(&mut self) {
//         unsafe {
//             // native_handle_close(self.ptr)
//             // native_handle_delete(self.ptr)
//         }
//     }
// }

#[test]
fn test_write_data() {
    let mut parcel = Parcel::new();

    assert_eq!(parcel.data(), []);
    assert_eq!(parcel.data_capacity(), 0);
    assert_eq!(parcel.data_avail(), 0);
    assert_eq!(parcel.data_position(), 0);

    assert!(parcel.set_data(&[1, 2, 3, 4, 5]).is_ok());

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

    assert!(parcel2.set_data(&[1, 2, 3, 4, 5]).is_ok());

    assert_eq!(parcel2.compare_data(&parcel), 1);

    unsafe {
        assert!(parcel2.set_data_size(3).is_ok());
    }

    assert_eq!(parcel2.compare_data(&parcel), -1);

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

    assert_eq!(parcel.read_bool(), false);
    assert_eq!(parcel.try_read_bool(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i8(), 0);
    assert_eq!(parcel.try_read_i8(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u16(), 0);
    assert_eq!(parcel.try_read_u16(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i32(), 0);
    assert_eq!(parcel.try_read_i32(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u32(), 0);
    assert_eq!(parcel.try_read_u32(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i64(), 0);
    assert_eq!(parcel.try_read_i64(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u64(), 0);
    assert_eq!(parcel.try_read_u64(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_f32(), 0.);
    assert_eq!(parcel.try_read_f32(), Err(Error::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_f64(), 0.);
    assert_eq!(parcel.try_read_f64(), Err(Error::NOT_ENOUGH_DATA));
    assert!(parcel.read_c_string().is_none());
    assert_eq!(parcel.read_string8().len(), 0);
    assert_eq!(parcel.try_read_string8(), Err(Error::NOT_ENOUGH_DATA));
    unsafe {
        assert_eq!(parcel.read_string16().size(), 0);
    }
    assert_eq!(parcel.try_read_string16(), Err(Error::UNEXPECTED_NULL));

    // unsafe {
    //     assert_eq!(
    //         parcel.try_read_strong_binder().err(),
    //         Some(Error::BAD_TYPE)
    //     );
    // }

    parcel.set_data(b"Hello, Binder!\0");

    // REVIEW: Are these endian-dependent?
    assert_eq!(parcel.read_bool(), true);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_bool().unwrap(), true);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i8(), 72);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_i8().unwrap(), 72);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_u16(), 25928);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_u16().unwrap(), 25928);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i32(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_i32().unwrap(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_u32(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_u32().unwrap(), 1819043144);
    assert_eq!(parcel.data_position(), 4);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_i64(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_i64().unwrap(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_u64(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_u64().unwrap(), 4764857262830019912);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_f32(), 1143139100000000000000000000.0);
    assert_eq!(parcel.data_position(), 4);
    assert_eq!(parcel.try_read_f32().unwrap(), 40.043392);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.read_f64(), 34732488246.197815);
    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.try_read_f64().unwrap(), 34732488246.197815);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.read_c_string().unwrap().to_bytes(),
        b"Hello, Binder!"
    );

    assert!(parcel.set_data_position(0).is_ok());

    // read/writeString uses a len field first which we didn't do in set_data above
    // and maybe some other metadata?
    let mut s = String8::new();

    s.append_bytes(b"Hello, Binder!");

    assert!(parcel.write_string8(&s).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let s = parcel.read_string8();

    assert_eq!(s.len(), 14);
    assert_eq!(s.as_slice(), b"Hello, Binder!");

    assert!(parcel.set_data_position(0).is_ok());

    let s = parcel.try_read_string8().unwrap();

    assert_eq!(s.len(), 14);
    assert_eq!(s.as_str(), "Hello, Binder!");

    // TODO:
    // try_readString16
    // readString16
    // readStrongBinder
    // try_readStrongBinder

    assert_eq!(&parcel.data()[4..], b"Hello, Binder!\0\0");
}

#[test]
fn test_utf8_utf16_conversions() {
    let mut parcel = Parcel::new();

    assert!(parcel.write_utf8_as_utf16("Hello, Binder!").is_ok());
    assert!(parcel.set_data_position(0).is_ok());
    // assert_eq!(&*parcel.read_utf8_from_utf16(), "Hello, Binder!");
    assert!(parcel.set_data_position(0).is_ok());
    // assert!(parcel.write_utf8_slice_as_utf16(&["str1", "str2", "str3"]).is_ok());
    // assert!(parcel.write_utf8_slice_as_utf16(&[
    //     String::from("str4"),
    //     String::from("str5"),
    //     String::from("str6"),
    // ]).is_ok());

    let mut s1 = String8::new();
    let mut s2 = String8::new();
    let mut s3 = String8::new();

    assert!(s1.append_bytes(b"Hello, Binder!").is_ok());
    assert!(s2.append_bytes(b"This is a utf8 string.").is_ok());
    assert!(s3.append_bytes(b"Some more text here.").is_ok());

    let str8s = [s1, s2, s3];

    // assert!(parcel.write_utf8_slice_as_utf16(&str8s).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    // assert_eq!(parcel.read_utf8_slice_from_utf16().unwrap(), ["str1", "str2", "str3"]);
    // assert_eq!(parcel.read_utf8_slice_from_utf16().unwrap(), ["str4", "str5", "str6"]);
    // assert_eq!(parcel.read_utf8_slice_from_utf16().unwrap(), [
    //     "Hello, Binder!",
    //     "This is a utf8 string.",
    //     "Some more text here.",
    // ]);
}
