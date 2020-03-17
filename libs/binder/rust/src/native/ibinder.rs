#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use super::libbinder_bindings::*;
use super::parcel::{Parcel, Parcelable};
use super::String16;
use super::utils::{AsNative, Sp};
use crate::error::{binder_status, BinderResult};
use std::os::raw::c_void;
use std::ptr;

pub type TransactionCode = u32;
pub type TransactionFlags = u32;

/// Rust wrapper around Binder remote objects. Encapsulates the C++ IBinder class.
#[repr(transparent)]
pub struct IBinder(pub(super) Sp<android_IBinder>);

/// Rust wrapper around Binder interfaces. Encapsulates the C++ IInterface class.
#[repr(transparent)]
pub struct IInterface(Sp<android_IInterface>);

impl IBinder {
    pub const FIRST_CALL_TRANSACTION: TransactionCode = android_IBinder_FIRST_CALL_TRANSACTION;
    pub const LAST_CALL_TRANSACTION: TransactionCode = android_IBinder_LAST_CALL_TRANSACTION;
    pub const PING_TRANSACTION: TransactionCode = android_IBinder_PING_TRANSACTION;
    pub const DUMP_TRANSACTION: TransactionCode = android_IBinder_DUMP_TRANSACTION;
    pub const SHELL_COMMAND_TRANSACTION: TransactionCode =
        android_IBinder_SHELL_COMMAND_TRANSACTION;
    pub const INTERFACE_TRANSACTION: TransactionCode = android_IBinder_INTERFACE_TRANSACTION;
    pub const SYSPROPS_TRANSACTION: TransactionCode = android_IBinder_SYSPROPS_TRANSACTION;
    pub const EXTENSION_TRANSACTION: TransactionCode = android_IBinder_EXTENSION_TRANSACTION;
    pub const DEBUG_PID_TRANSACTION: TransactionCode = android_IBinder_DEBUG_PID_TRANSACTION;

    pub const FLAG_ONEWAY: TransactionFlags = android_IBinder_FLAG_ONEWAY;
    pub const FLAG_PRIVATE_VENDOR: TransactionFlags = android_IBinder_FLAG_PRIVATE_VENDOR;

    /// Low-level interface to perform a generic operation on the object.
    pub unsafe fn transact(
        &mut self,
        code: TransactionCode,
        data: &Parcel,
        reply: &mut Parcel,
        flags: TransactionFlags,
    ) -> android_status_t {
        android_c_interface_IBinder_transact(
            self.0.as_native_mut(),
            code,
            data.as_native(),
            reply.as_native_mut(),
            flags,
        )
    }

    pub unsafe fn query_local_interface(
        &mut self,
        descriptor: &String16,
    ) -> IInterface {
        IInterface(Sp(android_c_interface_IBinder_queryLocalInterface(
            self.0.as_native_mut(),
            descriptor.as_native(),
        )))
    }

    pub unsafe fn get_interface_descriptor(&mut self) -> *const String16 {
        android_c_interface_IBinder_getInterfaceDescriptor(self.0.as_native_mut()) as *const _
    }

    // TODO: Implement virtual method wrappers for the rest of IBinder

    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

        
impl Parcelable for IBinder {
    type Deserialized = IBinder;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        let status = unsafe {
            android_Parcel_writeStrongBinder(parcel.as_native_mut(), self.0.as_native())
        };
        binder_status(status)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<IBinder> {
        let mut sp = ptr::null_mut();
        let status = unsafe {
            android_c_interface_Parcel_readStrongBinder(parcel.as_native(), &mut sp)
        };
        binder_status(status)
            .map(|_| {
                assert!(!sp.is_null());
                unsafe { IBinder(Sp(sp)) }
            })
    }
}

