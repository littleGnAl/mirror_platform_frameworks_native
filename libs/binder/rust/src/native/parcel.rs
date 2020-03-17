#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use super::binder_native::BinderNative;
use super::libbinder_bindings::*;
use super::utils::Sp;
use super::IBinder;
use crate::error::{binder_status, BinderError, BinderResult};
use crate::native::{status_t, IPCThreadState, String16, String8};
use crate::service::Binder;

use std::convert::TryInto;
use std::ffi::CStr;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;

use libc::{c_int, c_void, uid_t};

mod blob;
mod parcelable;

pub use self::blob::{Blob, Readable, Writable};
pub use self::parcelable::Parcelable;

/// Container for a message (data and object references) that can be sent through Binder.
///
/// A Parcel can contain both flattened data that will be unflattened on the
/// other side of the IPC (using the various methods here for writing specific
/// types, or the general [`Parcelable`] trait), and references to live Binder
/// objects that will result in the other side receiving a proxy Binder
/// connected with the original Binder in the Parcel.
// Docs copied from /framworks/base/core/java/android/os/Parcel.java
#[repr(transparent)]
pub struct Parcel(pub(super) android_Parcel);

impl Parcel {
    pub fn new() -> Self {
        let mut parcel = MaybeUninit::uninit();
        unsafe {
            android_Parcel_Parcel(parcel.as_mut_ptr());
            Self(parcel.assume_init())
        }
    }

    pub fn data(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                android_Parcel_data(&self.0),
                self.data_size().try_into().unwrap(),
            )
        }
    }

    /// Returns the total amount of data contained in the parcel.
    pub fn data_size(&self) -> size_t {
        unsafe { android_Parcel_dataSize(&self.0) }
    }

    /// Returns the amount of data remaining to be read from the parcel. That is,
    /// data_size() - data_position().
    pub fn data_avail(&self) -> size_t {
        unsafe { android_Parcel_dataAvail(&self.0) }
    }

    /// Returns the current position in the parcel data. Never more than dataSize().
    pub fn data_position(&self) -> size_t {
        unsafe { android_Parcel_dataPosition(&self.0) }
    }

    /// Returns the total amount of space in the parcel. This is always >= dataSize().
    /// The difference between it and dataSize() is the amount of room left until the parcel
    /// needs to re-allocate its data buffer.
    pub fn data_capacity(&self) -> size_t {
        unsafe { android_Parcel_dataCapacity(&self.0) }
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
    pub unsafe fn set_data_size(&mut self, size: size_t) -> BinderResult<()> {
        let status = unsafe { android_Parcel_setDataSize(&mut self.0, size) };

        binder_status(status)
    }

    /// Move the current read/write position in the parcel.
    pub fn set_data_position(&mut self, pos: size_t) -> BinderResult<()> {
        // pos: New offset in the parcel; must be between 0 and data_size().
        if pos > self.data_size() {
            return Err(BinderError::BAD_VALUE);
        }

        unsafe {
            android_Parcel_setDataPosition(&mut self.0, pos);
        }

        Ok(())
    }

    /// Change the capacity (current available space) of the parcel.
    pub fn set_data_capacity(&mut self, size: size_t) -> BinderResult<()> {
        // size: The new capacity of the parcel, in bytes. Can not be less than dataSize()
        // -- that is, you can not drop existing data with this method.
        if size < self.data_size() {
            return Err(BinderError::BAD_VALUE);
        }

        let status = unsafe { android_Parcel_setDataCapacity(&mut self.0, size) };

        binder_status(status)
    }

    pub fn set_data(&mut self, data: &[u8]) -> BinderResult<()> {
        let status = unsafe {
            android_Parcel_setData(&mut self.0, data.as_ptr(), data.len().try_into().unwrap())
        };

        binder_status(status)
    }

    /// The start offset and len are bounds checked by the original C++ code and return BAD_VALUE in such a case.
    pub fn append_from(&mut self, parcel: &Parcel, start: size_t, len: size_t) -> BinderResult<()> {
        let status = unsafe { android_Parcel_appendFrom(&mut self.0, &parcel.0, start, len) };

        binder_status(status)
    }

    pub fn compare_data(&mut self, other: &Parcel) -> c_int {
        unsafe { android_Parcel_compareData(&mut self.0, &other.0) }
    }

    pub fn allow_fds(&self) -> bool {
        unsafe { android_Parcel_allowFds(&self.0) }
    }

    pub fn push_allow_fds(&mut self, allowFds: bool) -> bool {
        unsafe { android_Parcel_pushAllowFds(&mut self.0, allowFds) }
    }

    pub fn restore_allow_fds(&mut self, allowFds: bool) {
        unsafe { android_Parcel_restoreAllowFds(&mut self.0, allowFds) }
    }

    pub fn has_file_descriptors(&self) -> bool {
        unsafe { android_Parcel_hasFileDescriptors(&self.0) }
    }

    /// Writes the RPC header.
    pub unsafe fn write_interface_token(&mut self, interface: &String16) -> BinderResult<()> {
        binder_status(android_Parcel_writeInterfaceToken(&mut self.0, interface))
    }

    /// Parses the RPC header, returning true if the interface name
    /// in the header matches the expected interface from the caller.
    ///
    /// Additionally, enforceInterface does part of the work of
    /// propagating the StrictMode policy mask, populating the current
    /// IPCThreadState, which as an optimization may optionally be
    /// passed in.
    pub unsafe fn enforce_interface(
        &self,
        interface: &String16,
        threadState: Option<&mut IPCThreadState>,
    ) -> bool {
        // It's valid to pass a nullptr for threadstate
        let threadState = threadState.map_or(ptr::null_mut(), |ts| ts as *mut _);

        android_Parcel_enforceInterface(&self.0, interface, threadState)
    }

    pub unsafe fn check_interface(&self, ibinder: &mut IBinder) -> bool {
        android_Parcel_checkInterface(&self.0, ibinder as *mut _ as *mut _)
    }

    pub fn free_data(&mut self) {
        unsafe { android_Parcel_freeData(&mut self.0) }
    }

    pub fn objects_count(&self) -> size_t {
        unsafe { android_Parcel_objectsCount(&self.0) }
    }

    pub fn error_check(&self) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_errorCheck(&self.0)) }
    }

    pub fn set_error(&mut self, err: status_t) {
        unsafe { android_Parcel_setError(&mut self.0, err) }
    }

    pub unsafe fn write_bytes(&mut self, data: &[u8]) -> BinderResult<()> {
        binder_status(android_Parcel_write(
            &mut self.0,
            data.as_ptr() as *const c_void,
            data.len().try_into().unwrap(),
        ))
    }

    // void*               writeInplace(size_t len);

    pub unsafe fn write_unpadded(&mut self, data: &[u8]) -> BinderResult<()> {
        binder_status(android_Parcel_writeUnpadded(
            &mut self.0,
            data.as_ptr() as *const c_void,
            data.len().try_into().unwrap(),
        ))
    }

    pub fn write_i32(&mut self, val: i32) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeInt32(&mut self.0, val)) }
    }

    pub fn write_u32(&mut self, val: u32) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeUint32(&mut self.0, val)) }
    }

    pub fn write_i64(&mut self, val: i64) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeInt64(&mut self.0, val)) }
    }

    pub fn write_u64(&mut self, val: u64) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeUint64(&mut self.0, val)) }
    }

    pub fn write_f32(&mut self, val: f32) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeFloat(&mut self.0, val)) }
    }

    pub fn write_f64(&mut self, val: f64) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeDouble(&mut self.0, val)) }
    }

    pub unsafe fn write_c_string(&mut self, str: &CStr) -> BinderResult<()> {
        binder_status(android_Parcel_writeCString(&mut self.0, str.as_ptr()))
    }

    pub fn write_string8(&mut self, str: &String8) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeString8(&mut self.0, &str.0)) }
    }

    pub fn write_string16(&mut self, str: &String16) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeString16(&mut self.0, str)) }
    }

    // status_t            writeString16(const std::optional<String16>& str);
    // status_t            writeString16(const std::unique_ptr<String16>& str);

    pub fn write_string16_bytes(&mut self, str: &[u16]) -> BinderResult<()> {
        let status = unsafe {
            android_Parcel_writeString163(&mut self.0, str.as_ptr(), str.len().try_into().unwrap())
        };

        binder_status(status)
    }

    // status_t            writeStrongBinder(const sp<IBinder>& val);

    pub fn write_binder<T: Binder>(&mut self, binder: &Sp<BinderNative<T>>) -> BinderResult<()> {
        unsafe {
            let binder_ptr = binder as *const Sp<BinderNative<T>>;
            binder_status(android_Parcel_writeStrongBinder(
                &mut self.0,
                binder_ptr.cast(),
            ))
        }
    }

    pub fn write_i32_slice(&mut self, array: &[i32]) -> BinderResult<()> {
        let len = array.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeInt32Array(
                &mut self.0,
                len,
                array.as_ptr(),
            ))
        }
    }

    pub fn write_u8_slice(&mut self, array: &[u8]) -> BinderResult<()> {
        let len = array.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeByteArray(
                &mut self.0,
                len,
                array.as_ptr(),
            ))
        }
    }

    pub fn write_bool(&mut self, val: bool) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeBool(&mut self.0, val)) }
    }

    pub fn write_u16(&mut self, val: u16) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeChar(&mut self.0, val)) }
    }

    pub fn write_i8(&mut self, val: i8) -> BinderResult<()> {
        unsafe { binder_status(android_Parcel_writeByte(&mut self.0, val)) }
    }

    // Take a UTF8 encoded string, convert to UTF16, write it to the parcel.
    pub fn write_utf8_as_utf16(&mut self, s: &str) -> BinderResult<()> {
        unsafe { self.write_string16(&s.into()) }
    }
    // status_t            writeUtf8AsUtf16(const std::string& str);
    // status_t            writeUtf8AsUtf16(const std::optional<std::string>& str);
    // status_t            writeUtf8AsUtf16(const std::unique_ptr<std::string>& str);
    // status_t            writeByteVector(const std::optional<std::vector<int8_t>>& val);
    // status_t            writeByteVector(const std::unique_ptr<std::vector<int8_t>>& val);
    // status_t            writeByteVector(const std::vector<int8_t>& val);
    // status_t            writeByteVector(const std::optional<std::vector<uint8_t>>& val);
    // status_t            writeByteVector(const std::unique_ptr<std::vector<uint8_t>>& val);
    // status_t            writeByteVector(const std::vector<uint8_t>& val);
    // status_t            writeInt32Vector(const std::optional<std::vector<int32_t>>& val);
    // status_t            writeInt32Vector(const std::unique_ptr<std::vector<int32_t>>& val);
    // status_t            writeInt32Vector(const std::vector<int32_t>& val);
    // status_t            writeInt64Vector(const std::optional<std::vector<int64_t>>& val);
    // status_t            writeInt64Vector(const std::unique_ptr<std::vector<int64_t>>& val);
    // status_t            writeInt64Vector(const std::vector<int64_t>& val);
    // status_t            writeUint64Vector(const std::optional<std::vector<uint64_t>>& val);
    // status_t            writeUint64Vector(const std::unique_ptr<std::vector<uint64_t>>& val);
    // status_t            writeUint64Vector(const std::vector<uint64_t>& val);
    // status_t            writeFloatVector(const std::optional<std::vector<float>>& val);
    // status_t            writeFloatVector(const std::unique_ptr<std::vector<float>>& val);
    // status_t            writeFloatVector(const std::vector<float>& val);
    // status_t            writeDoubleVector(const std::optional<std::vector<double>>& val);
    // status_t            writeDoubleVector(const std::unique_ptr<std::vector<double>>& val);
    // status_t            writeDoubleVector(const std::vector<double>& val);
    // status_t            writeBoolVector(const std::optional<std::vector<bool>>& val);
    // status_t            writeBoolVector(const std::unique_ptr<std::vector<bool>>& val);
    // status_t            writeBoolVector(const std::vector<bool>& val);
    // status_t            writeCharVector(const std::optional<std::vector<char16_t>>& val);
    // status_t            writeCharVector(const std::unique_ptr<std::vector<char16_t>>& val);
    // status_t            writeCharVector(const std::vector<char16_t>& val);
    // status_t            writeString16Vector(
    //                         const std::optional<std::vector<std::optional<String16>>>& val);
    // status_t            writeString16Vector(
    //                         const std::unique_ptr<std::vector<std::unique_ptr<String16>>>& val);
    // status_t            writeString16Vector(const std::vector<String16>& val);
    // status_t            writeUtf8VectorAsUtf16Vector(
    //                         const std::optional<std::vector<std::optional<std::string>>>& val);
    // status_t            writeUtf8VectorAsUtf16Vector(
    //                         const std::unique_ptr<std::vector<std::unique_ptr<std::string>>>& val);
    // status_t            writeUtf8VectorAsUtf16Vector(const std::vector<std::string>& val);
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
    // status_t            writeParcelableVector(const std::optional<std::vector<std::optional<T>>>& val);
    // template<typename T>
    // status_t            writeParcelableVector(const std::unique_ptr<std::vector<std::unique_ptr<T>>>& val);
    // template<typename T>
    // status_t            writeParcelableVector(const std::shared_ptr<std::vector<std::unique_ptr<T>>>& val);
    // template<typename T>
    // status_t            writeParcelableVector(const std::vector<T>& val);
    // template<typename T>
    // status_t            writeNullableParcelable(const std::optional<T>& parcelable);
    // template<typename T>
    // status_t            writeNullableParcelable(const std::unique_ptr<T>& parcelable);
    // status_t            writeParcelable(const Parcelable& parcelable);
    // template<typename T>
    // status_t            write(const Flattenable<T>& val);
    // template<typename T>
    // status_t            write(const LightFlattenable<T>& val);
    // template<typename T>
    // status_t            writeVectorSize(const std::vector<T>& val);
    // template<typename T>
    // status_t            writeVectorSize(const std::optional<std::vector<T>>& val);
    // template<typename T>
    // status_t            writeVectorSize(const std::unique_ptr<std::vector<T>>& val);

    /// Place a native_handle into the parcel (the native_handle's file-
    /// descriptors are dup'ed, so it is safe to delete the native_handle
    /// when this function returns).
    pub unsafe fn write_native_handle(&mut self, handle: &NativeHandle) -> BinderResult<()> {
        binder_status(android_Parcel_writeNativeHandle(&mut self.0, handle.0))
    }

    /// Place a file descriptor into the parcel.  The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    // TODO: takeOwnership probably shouldn't be publicly exposed
    pub unsafe fn write_file_descriptor(
        &mut self,
        fd: c_int,
        takeOwnership: bool,
    ) -> BinderResult<()> {
        binder_status(android_Parcel_writeFileDescriptor(
            &mut self.0,
            fd,
            takeOwnership,
        ))
    }

    /// Place a file descriptor into the parcel.  A dup of the fd is made, which
    /// will be closed once the parcel is destroyed.
    pub unsafe fn write_dup_file_descriptor(&mut self, fd: c_int) -> BinderResult<()> {
        binder_status(android_Parcel_writeDupFileDescriptor(&mut self.0, fd))
    }

    /// Place a Java "parcel file descriptor" into the parcel.  The given fd must remain
    /// valid for the lifetime of the parcel.
    /// The Parcel does not take ownership of the given fd unless you ask it to.
    // TODO: takeOwnership probably shouldn't be publicly exposed
    pub unsafe fn write_parcel_file_descriptor(
        &mut self,
        fd: c_int,
        takeOwnership: bool,
    ) -> BinderResult<()> {
        binder_status(android_Parcel_writeParcelFileDescriptor(
            &mut self.0,
            fd,
            takeOwnership,
        ))
    }

    /// Place a Java "parcel file descriptor" into the parcel.  A dup of the fd is made, which will
    /// be closed once the parcel is destroyed.
    pub unsafe fn write_dup_parcel_file_descriptor(&mut self, fd: c_int) -> BinderResult<()> {
        binder_status(android_Parcel_writeDupParcelFileDescriptor(&mut self.0, fd))
    }

    // Place a file descriptor into the parcel.  This will not affect the
    // semantics of the smart file descriptor. A new descriptor will be
    // created, and will be closed when the parcel is destroyed.
    // status_t            writeUniqueFileDescriptor(
    //                         const base::unique_fd& fd);
    // Place a vector of file desciptors into the parcel. Each descriptor is
    // dup'd as in writeDupFileDescriptor
    // status_t            writeUniqueFileDescriptorVector(
    //                         const std::optional<std::vector<base::unique_fd>>& val);
    // status_t            writeUniqueFileDescriptorVector(
    //                         const std::unique_ptr<std::vector<base::unique_fd>>& val);
    // status_t            writeUniqueFileDescriptorVector(
    //                         const std::vector<base::unique_fd>& val);

    /// Writes a blob to the parcel.
    /// If the blob is small, then it is stored in-place, otherwise it is
    /// transferred by way of an anonymous shared memory region. Prefer sending
    /// immutable blobs if possible since they may be subsequently transferred between
    /// processes without further copying whereas mutable blobs always need to be copied.
    /// The caller should call release() on the blob after writing its contents.
    // REVIEW: mutableCopy maybe shouldn't be part of the public API?
    // It's not currently clear whether or not we can make this fully safe.
    pub fn write_blob(&mut self, len: size_t, mutableCopy: bool) -> BinderResult<Blob<Writable>> {
        let mut blob = MaybeUninit::uninit();
        let status =
            unsafe { android_Parcel_writeBlob(&mut self.0, len, mutableCopy, blob.as_mut_ptr()) };

        binder_status(status).map(|_| Blob::new(unsafe { blob.assume_init()._base }))
    }

    /// Write an existing immutable blob file descriptor to the parcel.
    /// This allows the client to send the same blob to multiple processes
    /// as long as it keeps a dup of the blob file descriptor handy for later.
    pub unsafe fn write_dup_immutable_blob_file_descriptor(
        &mut self,
        fd: c_int,
    ) -> BinderResult<()> {
        binder_status(android_Parcel_writeDupImmutableBlobFileDescriptor(
            &mut self.0,
            fd,
        ))
    }

    // status_t            writeObject(const flat_binder_object& val, bool nullMetaData);

    /// Like Parcel.java's writeNoException().  Just writes a zero int32.
    /// Currently the native implementation doesn't do any of the StrictMode
    /// stack gathering and serialization that the Java implementation does.
    pub unsafe fn write_no_exception(&mut self) -> BinderResult<()> {
        binder_status(android_Parcel_writeNoException(&mut self.0))
    }

    pub fn read<P: Parcelable>(&self) -> P::Deserialized {
        P::deserialize(self).unwrap()
    }

    pub fn try_read<P: Parcelable>(&self) -> BinderResult<P::Deserialized> {
        P::deserialize(self)
    }

    pub fn write<P: Parcelable>(&mut self, parcelable: P) -> BinderResult<()> {
        parcelable.serialize(self)
    }

    pub fn read_to_bytes(&self, bytes: &mut [u8]) -> BinderResult<()> {
        let status = unsafe {
            android_Parcel_read(
                &self.0,
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len().try_into().unwrap(),
            )
        };

        binder_status(status)
    }

    // const void*         readInplace(size_t len) const;

    pub fn read_i32(&self) -> i32 {
        unsafe { android_Parcel_readInt32(&self.0) }
    }

    pub fn try_read_i32(&self) -> BinderResult<i32> {
        let mut int32 = 0;
        let result = unsafe { android_Parcel_readInt321(&self.0, &mut int32) };

        binder_status(result).map(|_| int32)
    }

    pub fn read_u32(&self) -> u32 {
        unsafe { android_Parcel_readUint32(&self.0) }
    }

    pub fn try_read_u32(&self) -> BinderResult<u32> {
        let mut uint32 = 0;
        let result = unsafe { android_Parcel_readUint321(&self.0, &mut uint32) };

        binder_status(result).map(|_| uint32)
    }

    pub fn read_i64(&self) -> i64 {
        unsafe { android_Parcel_readInt64(&self.0) }
    }

    pub fn try_read_i64(&self) -> BinderResult<i64> {
        let mut int64 = 0;
        let result = unsafe { android_Parcel_readInt641(&self.0, &mut int64) };

        binder_status(result).map(|_| int64)
    }

    pub fn read_u64(&self) -> u64 {
        unsafe { android_Parcel_readUint64(&self.0) }
    }

    pub fn try_read_u64(&self) -> BinderResult<u64> {
        let mut uint64 = 0;
        let result = unsafe { android_Parcel_readUint641(&self.0, &mut uint64) };

        binder_status(result).map(|_| uint64)
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn read_f32(&self) -> f32 {
        unsafe { android_Parcel_readFloat(&self.0) }
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn try_read_f32(&self) -> BinderResult<f32> {
        let mut float = 0.;
        let result = unsafe { android_Parcel_readFloat1(&self.0, &mut float) };

        binder_status(result).map(|_| float)
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn read_f64(&self) -> f64 {
        unsafe { android_Parcel_readDouble(&self.0) }
    }

    // REVIEW: The Rust spec doesn't currently guarantee any arbitrary bit pattern
    // can compose a f32/f64, so this may not actually be safe. Depends on how thoroughly
    // the C++ API validates it?
    pub fn try_read_f64(&self) -> BinderResult<f64> {
        let mut double = 0.;
        let result = unsafe { android_Parcel_readDouble1(&self.0, &mut double) };

        binder_status(result).map(|_| double)
    }

    // REVIEW: We probably don't want to just hand out rawptrs?:
    // intptr_t            readIntPtr() const;
    // status_t            readIntPtr(intptr_t *pArg) const;

    pub fn read_bool(&self) -> bool {
        // The C++ code creates the bool based on the value
        // being non-zero, so we shouldn't have to worry about
        // the bool being in an invalid state.
        unsafe { android_Parcel_readBool(&self.0) }
    }

    pub fn try_read_bool(&self) -> BinderResult<bool> {
        // The C++ code creates the bool based on the value
        // being non-zero, so we shouldn't have to worry about
        // the bool being in an invalid state.
        let mut b = false;
        let result = unsafe { android_Parcel_readBool1(&self.0, &mut b) };

        binder_status(result).map(|_| b)
    }

    pub fn read_u16(&self) -> u16 {
        unsafe { android_Parcel_readChar(&self.0) }
    }

    pub fn try_read_u16(&self) -> BinderResult<u16> {
        let mut ch = 0;
        let result = unsafe { android_Parcel_readChar1(&self.0, &mut ch) };

        binder_status(result).map(|_| ch)
    }

    pub fn read_i8(&self) -> i8 {
        unsafe { android_Parcel_readByte(&self.0) }
    }

    pub fn try_read_i8(&self) -> BinderResult<i8> {
        let mut byte = 0;
        let result = unsafe { android_Parcel_readByte1(&self.0, &mut byte) };

        binder_status(result).map(|_| byte)
    }

    // Read a UTF16 encoded string, convert to UTF8
    // status_t            readUtf8FromUtf16(std::string* str) const;
    // status_t            readUtf8FromUtf16(std::optional<std::string>* str) const;
    // status_t            readUtf8FromUtf16(std::unique_ptr<std::string>* str) const;

    pub fn read_c_string(&self) -> Option<&CStr> {
        let ptr = unsafe { android_Parcel_readCString(&self.0) };

        if ptr.is_null() {
            return None;
        }

        unsafe { Some(CStr::from_ptr(ptr)) }
    }

    pub fn read_string8(&self) -> String8 {
        // String8 has a non-trivial copy constructor, so C++ doesn't return it
        // by value. This means that bindgen emits a broken
        // android_Parcel_readString8, so we use the overloaded version that
        // writes to a parameter. See
        // https://github.com/rust-lang/rust-bindgen/issues/778
        // android_Parcel_readString8(&self.0)
        self.try_read_string8().unwrap_or(String8::new())
    }

    pub fn try_read_string8(&self) -> BinderResult<String8> {
        let mut string8 = String8::new();
        let result = unsafe { android_Parcel_readString81(&self.0, &mut string8.0) };

        binder_status(result).map(|_| string8)
    }

    pub fn try_read_string16(&self) -> BinderResult<String16> {
        let mut s = unsafe { String16::new() };
        let status = unsafe { android_Parcel_readString161(&self.0, &mut s) };

        binder_status(status).map(|_| s)
    }

    pub fn read_string16(&self) -> String16 {
        // String16 has a non-trivial copy constructor, so C++ doesn't return it
        // by value. This means that bindgen emits a broken
        // android_Parcel_readString16, so we use the overloaded version that
        // writes to a parameter. See
        // https://github.com/rust-lang/rust-bindgen/issues/778
        self.try_read_string16()
            .unwrap_or(unsafe { String16::new() })
    }

    // status_t            readString16(std::optional<String16>* pArg) const;
    // status_t            readString16(std::unique_ptr<String16>* pArg) const;

    pub unsafe fn read_string16_inplace(&self) -> &[u16] {
        let mut out_len = 0;
        let data = android_Parcel_readString16Inplace(&self.0, &mut out_len);

        std::slice::from_raw_parts(data, out_len.try_into().unwrap())
    }

    pub unsafe fn read_strong_binder(&self) -> Sp<IBinder> {
        // sp<IBinder> has a non-trivial copy constructor, so C++ doesn't return it
        // by value. This means that bindgen emits a broken
        // android_Parcel_readStrongBinder, so we use the overloaded version that
        // writes to a parameter. See
        // https://github.com/rust-lang/rust-bindgen/issues/778
        // android_Parcel_readStrongBinder(&self.0, &mut sp_binder)
        self.try_read_strong_binder().unwrap()
    }

    pub unsafe fn try_read_strong_binder(&self) -> BinderResult<Sp<IBinder>> {
        let mut sp_binder = Sp::null();
        let status = android_Parcel_readStrongBinder1(&self.0, &mut sp_binder as *mut _ as *mut _);

        binder_status(status).map(|_| sp_binder)
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
    // status_t            readParcelableVector(
    //                         std::optional<std::vector<std::optional<T>>>* val) const;
    // template<typename T>
    // status_t            readParcelableVector(
    //                         std::unique_ptr<std::vector<std::unique_ptr<T>>>* val) const;
    // template<typename T>
    // status_t            readParcelableVector(std::vector<T>* val) const;
    // status_t            readParcelable(Parcelable* parcelable) const;
    // template<typename T>
    // status_t            readParcelable(std::optional<T>* parcelable) const;
    // template<typename T>
    // status_t            readParcelable(std::unique_ptr<T>* parcelable) const;
    // template<typename T>
    // status_t            readStrongBinder(sp<T>* val) const;
    // template<typename T>
    // status_t            readNullableStrongBinder(sp<T>* val) const;
    // status_t            readStrongBinderVector(std::optional<std::vector<sp<IBinder>>>* val) const;
    // status_t            readStrongBinderVector(std::unique_ptr<std::vector<sp<IBinder>>>* val) const;
    // status_t            readStrongBinderVector(std::vector<sp<IBinder>>* val) const;
    // status_t            readByteVector(std::optional<std::vector<int8_t>>* val) const;
    // status_t            readByteVector(std::unique_ptr<std::vector<int8_t>>* val) const;
    // status_t            readByteVector(std::vector<int8_t>* val) const;
    // status_t            readByteVector(std::optional<std::vector<uint8_t>>* val) const;
    // status_t            readByteVector(std::unique_ptr<std::vector<uint8_t>>* val) const;
    // status_t            readByteVector(std::vector<uint8_t>* val) const;
    // status_t            readInt32Vector(std::optional<std::vector<int32_t>>* val) const;
    // status_t            readInt32Vector(std::unique_ptr<std::vector<int32_t>>* val) const;
    // status_t            readInt32Vector(std::vector<int32_t>* val) const;
    // status_t            readInt64Vector(std::optional<std::vector<int64_t>>* val) const;
    // status_t            readInt64Vector(std::unique_ptr<std::vector<int64_t>>* val) const;
    // status_t            readInt64Vector(std::vector<int64_t>* val) const;
    // status_t            readUint64Vector(std::optional<std::vector<uint64_t>>* val) const;
    // status_t            readUint64Vector(std::unique_ptr<std::vector<uint64_t>>* val) const;
    // status_t            readUint64Vector(std::vector<uint64_t>* val) const;
    // status_t            readFloatVector(std::optional<std::vector<float>>* val) const;
    // status_t            readFloatVector(std::unique_ptr<std::vector<float>>* val) const;
    // status_t            readFloatVector(std::vector<float>* val) const;
    // status_t            readDoubleVector(std::optional<std::vector<double>>* val) const;
    // status_t            readDoubleVector(std::unique_ptr<std::vector<double>>* val) const;
    // status_t            readDoubleVector(std::vector<double>* val) const;
    // status_t            readBoolVector(std::optional<std::vector<bool>>* val) const;
    // status_t            readBoolVector(std::unique_ptr<std::vector<bool>>* val) const;
    // status_t            readBoolVector(std::vector<bool>* val) const;
    // status_t            readCharVector(std::optional<std::vector<char16_t>>* val) const;
    // status_t            readCharVector(std::unique_ptr<std::vector<char16_t>>* val) const;
    // status_t            readCharVector(std::vector<char16_t>* val) const;
    // status_t            readString16Vector(
    //                         std::optional<std::vector<std::optional<String16>>>* val) const;
    // status_t            readString16Vector(
    //                         std::unique_ptr<std::vector<std::unique_ptr<String16>>>* val) const;
    // status_t            readString16Vector(std::vector<String16>* val) const;
    // status_t            readUtf8VectorFromUtf16Vector(
    //                         std::optional<std::vector<std::optional<std::string>>>* val) const;
    // status_t            readUtf8VectorFromUtf16Vector(
    //                         std::unique_ptr<std::vector<std::unique_ptr<std::string>>>* val) const;
    // status_t            readUtf8VectorFromUtf16Vector(std::vector<std::string>* val) const;
    // template<typename T>
    // status_t            read(Flattenable<T>& val) const;
    // template<typename T>
    // status_t            read(LightFlattenable<T>& val) const;
    // template<typename T>
    // status_t            resizeOutVector(std::vector<T>* val) const;
    // template<typename T>
    // status_t            resizeOutVector(std::optional<std::vector<T>>* val) const;
    // template<typename T>
    // status_t            resizeOutVector(std::unique_ptr<std::vector<T>>* val) const;
    // template<typename T>
    // status_t            reserveOutVector(std::vector<T>* val, size_t* size) const;
    // template<typename T>
    // status_t            reserveOutVector(std::optional<std::vector<T>>* val,
    //                                      size_t* size) const;
    // template<typename T>
    // status_t            reserveOutVector(std::unique_ptr<std::vector<T>>* val,
    //                                      size_t* size) const;

    /// Like Parcel.java's readExceptionCode().  Reads the first int32
    /// off of a Parcel's header, returning 0 or the negative error
    /// code on exceptions, but also deals with skipping over rich
    /// response headers.  Callers should use this to read & parse the
    /// response headers rather than doing it by hand.
    pub unsafe fn read_exception_code(&self) -> i32 {
        android_Parcel_readExceptionCode(&self.0)
    }

    /// Retrieve native_handle from the parcel. This returns a copy of the
    /// parcel's native_handle (the caller takes ownership). The caller
    /// must free the native_handle with native_handle_close() and
    /// native_handle_delete().
    pub unsafe fn read_native_handle(&self) -> NativeHandle {
        NativeHandle(android_Parcel_readNativeHandle(&self.0))
    }

    /// Retrieve a file descriptor from the parcel.  This returns the raw fd
    /// in the parcel, which you do not own -- use dup() to get your own copy.
    pub unsafe fn read_file_descriptor(&self) -> c_int {
        android_Parcel_readFileDescriptor(&self.0)
    }

    /// Retrieve a Java "parcel file descriptor" from the parcel.  This returns the raw fd
    /// in the parcel, which you do not own -- use dup() to get your own copy.
    pub unsafe fn read_parcel_file_descriptor(&self) -> c_int {
        android_Parcel_readParcelFileDescriptor(&self.0)
    }

    // Retrieve a smart file descriptor from the parcel.
    // status_t            readUniqueFileDescriptor(
    //                         base::unique_fd* val) const;
    // Retrieve a Java "parcel file descriptor" from the parcel.
    // status_t            readUniqueParcelFileDescriptor(base::unique_fd* val) const;
    // Retrieve a vector of smart file descriptors from the parcel.
    // status_t            readUniqueFileDescriptorVector(
    //                         std::optional<std::vector<base::unique_fd>>* val) const;
    // status_t            readUniqueFileDescriptorVector(
    //                         std::unique_ptr<std::vector<base::unique_fd>>* val) const;
    // status_t            readUniqueFileDescriptorVector(
    //                         std::vector<base::unique_fd>* val) const;
    // Reads a blob from the parcel.

    /// The caller should call release() on the blob after reading its contents. Though
    /// this will also happen on drop.
    // REVIEW: It's not currently clear whether or not we can make this fully safe.
    pub fn read_blob(&self, len: size_t) -> BinderResult<Blob<Readable>> {
        let mut blob = MaybeUninit::uninit();
        let status = unsafe { android_Parcel_readBlob(&self.0, len, blob.as_mut_ptr()) };

        binder_status(status).map(|_| Blob::new(unsafe { blob.assume_init()._base }))
    }

    // const flat_binder_object* readObject(bool nullMetaData) const;

    /// Explicitly close all file descriptors in the parcel.
    pub unsafe fn close_file_descriptors(&mut self) {
        android_Parcel_closeFileDescriptors(&mut self.0)
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
        android_Parcel_replaceCallingWorkSourceUid(&mut self.0, uid)
    }

    /// Returns the work source provided by the caller. This can only be trusted for trusted calling
    /// uid.
    pub unsafe fn read_calling_work_source_uid(&self) -> uid_t {
        android_Parcel_readCallingWorkSourceUid(&self.0)
    }

    /// There's also a `getBlobAshmemSize`, but it seems to return the same field
    /// as this method.
    pub fn get_open_ashmem_size(&self) -> size_t {
        unsafe { android_Parcel_getOpenAshmemSize(&self.0) }
    }
}

impl Drop for Parcel {
    fn drop(&mut self) {
        // Run the C++ Parcel complete object destructor
        unsafe { android_Parcel_Parcel_destructor(&mut self.0) }
        // REVIEW: Is this safe? Since there's a mutable reference to self
        // briefly after the destructor is called
    }
}

// TODO: Move to better location?
pub struct NativeHandle(*mut native_handle);

impl Drop for NativeHandle {
    fn drop(&mut self) {
        unsafe {
            // native_handle_close(self.0)
            // native_handle_delete(self.0)
        }
    }
}

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
    assert_eq!(
        parcel2.append_from(&parcel, 11, 10),
        Err(BinderError::BAD_VALUE)
    );
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
    assert_eq!(parcel.try_read_bool(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i8(), 0);
    assert_eq!(parcel.try_read_i8(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u16(), 0);
    assert_eq!(parcel.try_read_u16(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i32(), 0);
    assert_eq!(parcel.try_read_i32(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u32(), 0);
    assert_eq!(parcel.try_read_u32(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_i64(), 0);
    assert_eq!(parcel.try_read_i64(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_u64(), 0);
    assert_eq!(parcel.try_read_u64(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_f32(), 0.);
    assert_eq!(parcel.try_read_f32(), Err(BinderError::NOT_ENOUGH_DATA));
    assert_eq!(parcel.read_f64(), 0.);
    assert_eq!(parcel.try_read_f64(), Err(BinderError::NOT_ENOUGH_DATA));
    assert!(parcel.read_c_string().is_none());
    assert_eq!(parcel.read_string8().len(), 0);
    assert_eq!(parcel.try_read_string8(), Err(BinderError::NOT_ENOUGH_DATA));
    unsafe {
        assert_eq!(parcel.read_string16().size(), 0);
    }
    assert_eq!(
        parcel.try_read_string16(),
        Err(BinderError::UNEXPECTED_NULL)
    );

    unsafe {
        assert_eq!(
            parcel.try_read_strong_binder().err(),
            Some(BinderError::BAD_TYPE)
        );
    }

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
    assert_eq!(s.as_slice(), b"Hello, Binder!");

    // TODO:
    // try_readString16
    // readString16
    // readStrongBinder
    // try_readStrongBinder

    assert_eq!(&parcel.data()[4..], b"Hello, Binder!\0\0");
}
