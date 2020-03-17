#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use super::libbinder_bindings::android_String16 as String16;
use super::libbinder_bindings::*;
use super::utils::{
    Class, Method, RefBase, RefBaseVFns, RefBaseVTable, RefBaseVTablePtr, Sp, VirtualBase, RTTI,
};
use super::IBinder;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::ptr;

// sp<IBinder> IServiceManager::getService( const String16& name) const;
type getServiceMethod =
    Option<unsafe extern "C" fn(*mut Sp<IBinder>, *const IServiceManager, name: *const String16)>;

/// C++ vtable for `android::IServiceManager`
#[repr(C)]
#[derive(Debug)]
pub struct IServiceManagerVTable {
    _vbase_offset: isize,
    _offset_to_top: isize,
    _rtti: *const RTTI,
    vfns: IServiceManagerVFns,
    _vcall_offset_0: isize,
    _vcall_offset_1: isize,
    _vcall_offset_2: isize,
    _vcall_offset_3: isize,
    _vcall_offset_4: isize,
    _base_vtable: RefBaseVTable,
}

/// C++ vtable for `android::IServiceManager`, starting at the virtual table
/// address point
#[repr(C)]
#[derive(Debug)]
pub struct IServiceManagerVFns {
    _ZN7android15IServiceManagerD0Ev: *const Method,
    _ZN7android15IServiceManagerD2Ev: *const Method,
    onAsBinder: *const Method,
    getInterfaceDescriptor: Option<unsafe extern "C" fn(*const IServiceManager) -> *const String16>,
    getService: getServiceMethod,
    checkService: getServiceMethod,
    addService: Option<
        unsafe extern "C" fn(
            *const IServiceManager,
            *const String16,
            *const Sp<IBinder>,
            bool,
            i32,
        ) -> android_status_t,
    >,
    listServices:
        Option<unsafe extern "C" fn(*const IServiceManager, dumpsysFlags: c_int) -> android_Vector>,
    waitForService: getServiceMethod,
    isDeclared: Option<unsafe extern "C" fn(*const IServiceManager, *const String16) -> bool>,
}

type IServiceManagerVTablePtr = *const IServiceManagerVFns;

inherit_virtual!(IServiceManager : RefBase [IServiceManagerVTable @ 3]);

/// Service manager for C++ services.
///
/// This interface is only for legacy ABI compatibility. An AIDL-based
/// implementation is available in interfaces::IServiceManager.
#[repr(C)]
pub struct IServiceManager {
    vtable: IServiceManagerVTablePtr,
    vtable_RefBase: RefBaseVTablePtr,
    mRefs: *mut android_RefBase_weakref_impl,
}

#[test]
fn bindgen_test_layout_IServiceManager() {
    assert_eq!(
        ::std::mem::size_of::<IServiceManager>(),
        24usize,
        concat!("Size of: ", stringify!(IServiceManager))
    );
    assert_eq!(
        ::std::mem::align_of::<IServiceManager>(),
        8usize,
        concat!("Alignment of ", stringify!(IServiceManager))
    );
}

impl IServiceManager {
    // Must match values in IServiceManager.aidl
    /// Allows services to dump sections according to priorities.
    pub const DUMP_FLAG_PRIORITY_CRITICAL: c_int =
        android_IServiceManager_DUMP_FLAG_PRIORITY_CRITICAL;
    pub const DUMP_FLAG_PRIORITY_HIGH: c_int = android_IServiceManager_DUMP_FLAG_PRIORITY_HIGH;
    pub const DUMP_FLAG_PRIORITY_NORMAL: c_int = android_IServiceManager_DUMP_FLAG_PRIORITY_NORMAL;
    /// Services are by default registered with a DEFAULT dump priority. DEFAULT
    /// priority has the same priority as NORMAL priority but the services are
    /// not called with dump priority arguments.
    pub const DUMP_FLAG_PRIORITY_DEFAULT: c_int =
        android_IServiceManager_DUMP_FLAG_PRIORITY_DEFAULT;
    pub const DUMP_FLAG_PRIORITY_ALL: c_int = android_IServiceManager_DUMP_FLAG_PRIORITY_ALL;
    pub const DUMP_FLAG_PROTO: c_int = android_IServiceManager_DUMP_FLAG_PROTO;

    #[inline]
    pub unsafe fn new() -> Self {
        let mut __bindgen_tmp = ::std::mem::MaybeUninit::uninit();
        android_IServiceManager_IServiceManager(__bindgen_tmp.as_mut_ptr());
        __bindgen_tmp.assume_init()
    }

    /// Return list of all existing services.
    pub unsafe fn listServices(&self, dumpsysFlags: c_int) -> android_Vector {
        (*self.vtable).listServices.unwrap()(self, dumpsysFlags)
    }

    // for ABI compatibility
    pub unsafe fn getInterfaceDescriptor(&self) -> *const String16 {
        (*self.vtable).getInterfaceDescriptor.unwrap()(self)
    }

    /// Retrieve an existing service, blocking for a few seconds if it doesn't
    /// yet exist.
    pub unsafe fn getService(&self, name: &String16) -> Sp<IBinder> {
        let mut sm = Sp::null();
        (*self.vtable).getService.unwrap()(&mut sm, self, name);
        sm
    }

    /// Retrieve an existing service, non-blocking.
    pub unsafe fn checkService(&self, name: &String16) -> Sp<IBinder> {
        let mut sm = Sp::null();
        (*self.vtable).checkService.unwrap()(&mut sm, self, name);
        sm
    }

    /// Register a service.
    pub unsafe fn addService(
        &self,
        name: &String16,
        service: *const Sp<IBinder>,
        allowIsolated: bool,
        dumpsysFlags: i32,
    ) -> android_status_t {
        (*self.vtable).addService.unwrap()(self, name, service, allowIsolated, dumpsysFlags)
    }

    /// Efficiently wait for a service.
    ///
    /// Returns nullptr only for permission problem or fatal error.
    pub unsafe fn waitForService(&self, name: &String16) -> Sp<IBinder> {
        let mut sm = Sp::null();
        (*self.vtable).waitForService.unwrap()(&mut sm, self, name);
        sm
    }

    /// Check if a service is declared (e.g. VINTF manifest).
    ///
    /// If this returns true, waitForService should always be able to return the
    /// service.
    pub unsafe fn isDeclared(&self, name: &String16) -> bool {
        (*self.vtable).isDeclared.unwrap()(self, name)
    }
}

extern "C" {
    #[link_name = "\u{1}_ZN7android21defaultServiceManagerEv"]
    pub fn android_defaultServiceManager(_: *mut Sp<IServiceManager>);
}

pub unsafe fn defaultServiceManager() -> Sp<IServiceManager> {
    let mut ptr = Sp::null();
    android_defaultServiceManager(&mut ptr);
    ptr
}
