#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use super::ibinder::IBinderVFns;
use super::libbinder_bindings::*;
use super::utils::{
    Class, Method, RefBase, RefBaseVFns, RefBaseVTable, RefBaseVTablePtr, Sp, VirtualBase, RTTI,
};
use super::Parcel;
use crate::error::BinderError;
use crate::service::Binder;
use std::os::raw::c_char;
use std::ptr;

/// Rust wrapper around Binder remotable objects. Implements the C++ BBinder
/// class, and therefore implements the C++ IBinder interface.
// TODO: Should this own a T instead of taking a mutable borrow?
#[repr(C)]
pub struct BinderNative<'a, T: Binder> {
    // Because this struct derives from C++ BBinder, the first 40 bytes must
    // stay in this exact layout..
    vtable: BBinderVTablePtr,
    __opaque: [c_char; 16],
    vtable_RefBase: RefBaseVTablePtr,
    _mRefs: *mut android_RefBase_weakref_impl,

    rust_object: &'a mut T,
}

extern "C" {
    // C++ complete destructor for BBinder. The complete destructor destructs
    // itself and its base, but also any virtual bases. We need to use this so
    // RefBase gets destructed, but bindgen doesn't generate a binding for it.
    #[link_name = "\u{1}_ZN7android7BBinderD0Ev"]
    fn android_BBinder_BBinder_destructor_complete(this: *mut android_BBinder);
}

/// C++ vtable for `android::BBinder`
#[repr(C)]
pub struct BBinderVTable {
    _vbase_offset: isize,
    _offset_to_top: isize,
    _rtti: *const RTTI,
    vfns: BBinderVFns,
    _vcall_offset_0: isize,
    _vcall_offset_1: isize,
    _vcall_offset_2: isize,
    _vcall_offset_3: isize,
    _vcall_offset_4: isize,
    _base_vtable: RefBaseVTable,
}

/// C++ vtable for `android::BBinder` starting at virtual table address point
#[repr(C)]
struct BBinderVFns {
    base: IBinderVFns,
    onTransact: *const Method,
}

type BBinderVTablePtr = *const BBinderVFns;

unsafe impl<'a, T: Binder> Class for BinderNative<'a, T> {
    type VTable = BBinderVTable;
    const VPTR_INDEX: isize = 3;
}

unsafe impl<'a, T: Binder> VirtualBase<RefBase> for BinderNative<'a, T> {
    fn as_virtual_base(&mut self) -> &mut RefBase {
        unsafe {
            &mut *(self as *mut _ as *mut u8)
                .offset(self.vtable()._vbase_offset)
                .cast()
        }
    }
}

fn unimplemented_complete_destructor() {
    unimplemented!("Complete object destructor thunk not implemented yet!");
}

fn unimplemented_deleting_destructor() {
    unimplemented!("Deleting object destructor thunk not implemented yet!");
}

impl<'a, T: 'a + Binder> BinderNative<'a, T> {
    /// Manually constructed VTable for BBinder which overrides the virtual
    /// method `onTransact` with `Self::on_transact`. The rest of the vtable is
    /// identical to one for a BBinder object.
    const BinderNativeVTable: BBinderVTable = BBinderVTable {
        _vbase_offset: 24,
        _offset_to_top: 0,
        _rtti: ptr::null(),
        vfns: BBinderVFns {
            base: IBinderVFns {
                queryLocalInterface: android_IBinder_queryLocalInterface as *const _,
                getInterfaceDescriptor: android_BBinder_getInterfaceDescriptor as *const _,
                isBinderAlive: Some(android_BBinder_isBinderAlive),
                pingBinder: Some(android_BBinder_pingBinder),
                dump: android_BBinder_dump as *const _,
                transact: Some(android_BBinder_transact),
                linkToDeath: android_BBinder_linkToDeath as *const _,
                unlinkToDeath: android_BBinder_unlinkToDeath as *const _,
                checkSubclass: android_IBinder_checkSubclass as *const _,
                attachObject: android_BBinder_attachObject as *const _,
                findObject: android_BBinder_findObject as *const _,
                detachObject: android_BBinder_detachObject as *const _,
                localBinder: android_BBinder_localBinder as *const _,
                remoteBinder: android_IBinder_remoteBinder as *const _,
                _complete_destructor: android_BBinder_BBinder_destructor as *const _,
                _deleting_destructor: android_BBinder_BBinder_destructor_complete as *const _,
            },
            onTransact: Self::on_transact as *const _,
        },
        _vcall_offset_0: 0,
        _vcall_offset_1: 0,
        _vcall_offset_2: 0,
        _vcall_offset_3: 0,
        _vcall_offset_4: -24,
        _base_vtable: RefBaseVTable {
            _offset_to_top: -24,
            _rtti: ptr::null(),
            vfns: RefBaseVFns {
                _complete_destructor: unimplemented_complete_destructor as *const _,
                _deleting_destructor: unimplemented_deleting_destructor as *const _,
                onFirstRef: android_RefBase_onFirstRef as *const _,
                onLastStrongRef: android_RefBase_onLastStrongRef as *const _,
                onIncStrongAttempted: android_RefBase_onIncStrongAttempted as *const _,
                onLastWeakRef: android_RefBase_onLastWeakRef as *const _,
            },
        },
    };

    pub fn new(rust_object: &'a mut T) -> Sp<BinderNative<'a, T>> {
        let mut obj = Sp::new(|obj: *mut BinderNative<'a, T>| unsafe {
            android_BBinder_BBinder(obj as *mut android_BBinder);
            (*obj).vtable = &Self::BinderNativeVTable.vfns as *const _;
            (*obj).vtable_RefBase = &Self::BinderNativeVTable._base_vtable.vfns as *const _;
        });
        unsafe {
            (*obj.as_mut_ptr()).rust_object = rust_object;
            obj.assume_init()
        }
    }

    // Callback invoked from C++
    unsafe fn on_transact(
        &mut self,
        code: u32,
        data: *const Parcel,
        reply: *mut Parcel,
        flags: u32,
    ) -> android_status_t {
        match self
            .rust_object
            .on_transact(code, &*data, &mut *reply, flags)
        {
            Ok(()) => BinderError::OK as i32,
            Err(e) => e as i32,
        }
    }
}
