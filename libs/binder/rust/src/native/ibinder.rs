#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use super::libbinder_bindings::*;
use super::parcel::Parcel;
use super::utils::{Class, Method, RefBase, RefBaseVTable, RefBaseVTablePtr, VirtualBase, RTTI};
use std::os::raw::c_void;
use std::ptr;

// virtual status_t IBinder::transact(uint32_t code, const Parcel& data,
//                                    Parcel* reply, uint32_t flags = 0);
pub(crate) type TransactMethod = Option<
    unsafe extern "C" fn(
        this: *mut c_void,
        code: u32,
        data: *const android_Parcel,
        reply: *mut android_Parcel,
        flags: u32,
    ) -> android_status_t,
>;

/// C++ vtable for `android::IBinder`
#[repr(C)]
pub struct IBinderVTable {
    pub(crate) _vbase_offset: isize,
    pub(crate) _offset_to_top: isize,
    pub(crate) _rtti: *const RTTI,
    pub(crate) vtable: IBinderVFns,
    pub(crate) _vcall_offset_0: isize,
    pub(crate) _vcall_offset_1: isize,
    pub(crate) _vcall_offset_2: isize,
    pub(crate) _vcall_offset_3: isize,
    pub(crate) _vcall_offset_4: isize,
    pub(crate) _base_vtable: RefBaseVTable,
}

/// C++ vtable for `android::IBinder` starting at vtable address point
#[repr(C)]
pub struct IBinderVFns {
    pub(crate) queryLocalInterface: *const Method,
    pub(crate) getInterfaceDescriptor: *const Method,
    pub(crate) isBinderAlive: Option<unsafe extern "C" fn(*mut c_void) -> bool>,
    pub(crate) pingBinder: Option<unsafe extern "C" fn(*mut c_void) -> android_status_t>,
    pub(crate) dump: *const Method,
    pub(crate) transact: TransactMethod,
    pub(crate) linkToDeath: *const Method,
    pub(crate) unlinkToDeath: *const Method,
    pub(crate) checkSubclass: *const Method,
    pub(crate) attachObject: *const Method,
    pub(crate) findObject: *const Method,
    pub(crate) detachObject: *const Method,
    pub(crate) localBinder: *const Method,
    pub(crate) remoteBinder: *const Method,
    pub(crate) _complete_destructor: *const Method,
    pub(crate) _deleting_destructor: *const Method,
}

type IBinderVTablePtr = *const IBinderVFns;

/// C++ Class android::IBinder
#[repr(C)]
pub struct IBinder {
    pub vtable: IBinderVTablePtr,
    vtable_RefBase: RefBaseVTablePtr,
    mRefs: *mut android_RefBase_weakref_impl,
}

inherit_virtual!(IBinder : RefBase [IBinderVTable @ 3]);

pub type TransactionCode = u32;
pub type TransactionFlags = u32;

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
        data: *const Parcel,
        reply: *mut Parcel,
        flags: TransactionFlags,
    ) -> android_status_t {
        (*self.vtable).transact.unwrap()(
            self as *mut _ as *mut _,
            code,
            data as *const _,
            reply as *mut _,
            flags,
        )
    }

    // TODO: Implement virtual method wrappers for the rest of IBinder
}
