#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use super::libbinder_bindings::*;
use super::parcel::Parcel;
use super::utils::{AsNative, String16};
use crate::error::{binder_status, BinderResult};
use crate::service::Binder;

/// Rust wrapper around Binder remotable objects. Implements the C++ BBinder
/// class, and therefore implements the C++ IBinder interface.
#[repr(C)]
pub struct BinderNative<T: Binder> {
    wrapper: *mut android_sp<android_c_interface_BinderNative>,
    rust_object: *mut T,
}

impl<T: Binder> BinderNative<T> {
    pub fn new(rust_object: Box<T>) -> BinderNative<T> {
        unsafe {
            let rust_object = Box::into_raw(rust_object);
            let descriptor: String16 = T::INTERFACE_DESCRIPTOR.into();
            let wrapper = android_c_interface_NewBinderNative(rust_object.cast(), descriptor.as_native(), Some(Self::on_transact));
            BinderNative {
                wrapper,
                rust_object,
            }
        }
    }

    unsafe extern "C" fn on_transact(
        object: *mut RustObject,
        code: u32,
        data: *const android_Parcel,
        reply: *mut android_Parcel,
        flags: u32,
    ) -> android_status_t {
        match (*(object as *mut T)).on_transact(
            code,
            &Parcel::wrap(data as *mut _),
            &mut Parcel::wrap(reply),
            flags,
        ) {
            Ok(()) => 0i32,
            Err(e) => e as i32,
        }
    }

    pub fn writeToParcel(&self, parcel: &mut Parcel) -> BinderResult<()> {
        let status = unsafe {
            android_c_interface_BinderNative_writeToParcel(self.wrapper, parcel.as_native_mut())
        };
        binder_status(status)
    }
}
