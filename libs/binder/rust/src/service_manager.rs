use crate::error::{binder_status, Result};
use crate::proxy::Interface;
use crate::sys::libbinder_bindings::*;
use crate::utils::{AsNative, Sp, Str16, String16};

use std::ffi::c_void;
use std::ptr;

wrap_sp! {
    /// Service manager for C++ services.
    ///
    /// This interface uses the legacy IServiceManager ABI from Binder. An
    /// [AIDL-based implementation](crate::interfaces::IServiceManager) is also
    /// available.
    // TODO: We should decide which interface to expose in this crate (or keep
    // both). Delegating to the binder `IServiceManager` class (via this struct)
    // is fine, but deprecated. However, our own hand-written AIDL
    // implementation in `interfaces::IServiceManager` is brittle until we have
    // a Rust backend for the AIDL compiler.
    pub struct ServiceManager(Sp<android_IServiceManager>) {
        getter: android_c_interface_Sp_getIServiceManager,
        destructor: android_c_interface_Sp_DropIServiceManager,
        clone: android_c_interface_Sp_CloneIServiceManager,
    }
}

#[repr(i32)]
pub enum DumpFlags {
    // Must match values in IServiceManager.aidl
    /// Allows services to dump sections according to priorities.
    PriorityCritical = android_IServiceManager_DUMP_FLAG_PRIORITY_CRITICAL,
    PriorityHigh = android_IServiceManager_DUMP_FLAG_PRIORITY_HIGH,
    PriorityNormal = android_IServiceManager_DUMP_FLAG_PRIORITY_NORMAL,
    /// Services are by default registered with a Default dump priority. Default
    /// priority has the same priority as Normal priority but the services are
    /// not called with dump priority arguments.
    PriorityDefault = android_IServiceManager_DUMP_FLAG_PRIORITY_DEFAULT,
    PriorityAll = android_IServiceManager_DUMP_FLAG_PRIORITY_ALL,
    Proto = android_IServiceManager_DUMP_FLAG_PROTO,
}

impl Default for DumpFlags {
    fn default() -> DumpFlags {
        DumpFlags::PriorityDefault
    }
}

impl Default for ServiceManager {
    fn default() -> ServiceManager {
        unsafe { ServiceManager::from_raw(android_c_interface_DefaultServiceManager()).unwrap() }
    }
}

impl ServiceManager {
    /// Return list of all existing services.
    pub fn list_services(&mut self, dump_flags: DumpFlags) -> Vec<String16> {
        unsafe extern "C" fn callback(service: *const android_String16, context: *mut c_void) {
            let services = &mut *(context as *mut Vec<String16>);
            services.push(Str16::from_ptr(service).to_owned());
        }

        let mut services = Vec::new();
        unsafe {
            android_c_interface_IServiceManager_listServices(
                self.0.as_native_mut(),
                dump_flags as i32,
                Some(callback),
                &mut services as *mut _ as *mut _,
            )
        }
        services
    }

    /// Retrieve an existing service, blocking for a few seconds if it doesn't
    /// yet exist.
    pub fn get_service(&self, name: &str) -> Option<Interface> {
        unsafe {
            Interface::from_raw(android_c_interface_IServiceManager_getService(
                self.0.as_native(),
                String16::from(name).as_native(),
            ))
        }
    }

    /// Retrieve an existing service, non-blocking.
    pub fn check_service(&self, name: &str) -> Option<Interface> {
        unsafe {
            Interface::from_raw(android_c_interface_IServiceManager_checkService(
                self.0.as_native(),
                String16::from(name).as_native(),
            ))
        }
    }

    /// Register a service.
    pub fn add_service(
        &mut self,
        name: &str,
        service: Interface,
        allow_isolated: bool,
        dump_flags: DumpFlags,
    ) -> Result<()> {
        let status = unsafe {
            android_c_interface_IServiceManager_addService(
                self.0.as_native_mut(),
                String16::from(name).as_native(),
                service.as_native(),
                allow_isolated,
                dump_flags as i32,
            )
        };
        binder_status(status)
    }

    /// Efficiently wait for a service.
    ///
    /// Returns nullptr only for permission problem or fatal error.
    pub fn wait_for_service(&mut self, name: &str) -> Option<Interface> {
        unsafe {
            Interface::from_raw(android_c_interface_IServiceManager_waitForService(
                self.0.as_native_mut(),
                String16::from(name).as_native(),
            ))
        }
    }

    /// Check if a service is declared (e.g. VINTF manifest).
    ///
    /// If this returns true, waitForService should always be able to return the
    /// service.
    pub fn is_declared(&mut self, name: &str) -> bool {
        unsafe {
            android_c_interface_IServiceManager_isDeclared(
                self.0.as_native_mut(),
                String16::from(name).as_native(),
            )
        }
    }
}
