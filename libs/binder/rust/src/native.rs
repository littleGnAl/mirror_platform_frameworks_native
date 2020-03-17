use crate::error::{binder_status, Result};
use crate::parcel::Parcel;
use crate::proxy::Interface;
use crate::sys::libbinder_bindings::*;
use crate::utils::{AsNative, Sp, String16};
use crate::{TransactionCode, TransactionFlags};

use std::ops::{Deref, DerefMut};
use std::ptr;

/// Rust wrapper around Binder remotable objects.
///
/// Implements the C++ `BBinder` class, and therefore implements the C++
/// `IBinder` interface.
#[repr(C)]
pub struct Service<T: Binder> {
    wrapper: Sp<android_c_interface_RustBBinder>,
    rust_object: *mut T,
}

impl<T: Binder> Service<T> {
    pub fn new(rust_object: Box<T>) -> Service<T> {
        unsafe {
            let rust_object = Box::into_raw(rust_object);
            let descriptor: String16 = T::INTERFACE_DESCRIPTOR.into();
            let wrapper = android_c_interface_NewRustBBinder(
                rust_object.cast(),
                descriptor.as_native(),
                Some(Self::on_transact),
                Some(Self::on_destroy),
            );
            Service {
                wrapper: Sp(wrapper.cast()),
                rust_object,
            }
        }
    }

    pub fn set_extension(&mut self, extension: &Interface) {
        unsafe {
            android_c_interface_RustBBinder_setExtension(
                self.wrapper.as_native_mut(),
                extension.as_native(),
            )
        }
    }

    pub fn get_extension(&mut self) -> Result<Option<Interface>> {
        let mut out = ptr::null_mut();
        let status = unsafe {
            android_c_interface_RustBBinder_getExtension(self.wrapper.as_native_mut(), &mut out)
        };
        let ibinder = unsafe { Interface::from_raw(out) };

        binder_status(status).map(|_| ibinder)
    }
}

/// A struct that is remotable via Binder.
///
/// This is a low-level interface that should normally be automatically
/// generated from AIDL.
pub trait Binder {
    const INTERFACE_DESCRIPTOR: &'static str;

    /// Handle and reply to a request to invoke a transaction on this object.
    ///
    /// `reply` may be [`None`] if the sender does not expect a reply.
    fn on_transact(
        &mut self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        flags: TransactionFlags,
    ) -> Result<()>;
}

impl Binder for () {
    const INTERFACE_DESCRIPTOR: &'static str = "";

    fn on_transact(
        &mut self,
        _code: TransactionCode,
        _data: &Parcel,
        _reply: Option<&mut Parcel>,
        _flags: TransactionFlags,
    ) -> Result<()> {
        Ok(())
    }
}

impl<T: Binder> Service<T> {
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
            Some(&mut Parcel::wrap(reply)),
            flags,
        ) {
            Ok(()) => 0i32,
            Err(e) => e as i32,
        }
    }

    unsafe extern "C" fn on_destroy(object: *mut RustObject) {
        ptr::drop_in_place(object as *mut T)
    }

    pub(crate) fn write_to_parcel(&self, parcel: &mut Parcel) -> Result<()> {
        let status = unsafe {
            android_c_interface_RustBBinder_writeToParcel(
                self.wrapper.as_native(),
                parcel.as_native_mut(),
            )
        };
        binder_status(status)
    }
}

impl<T: Binder> Drop for Service<T> {
    fn drop(&mut self) {
        unsafe {
            android_c_interface_Sp_DropRustBBinder(self.wrapper.as_native_mut());
        }
    }
}

impl<T: Binder> Deref for Service<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.rust_object }
    }
}

impl<T: Binder> DerefMut for Service<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.rust_object }
    }
}

impl<B: Binder> From<Service<B>> for Interface {
    fn from(mut binder_native: Service<B>) -> Self {
        unsafe {
            let ibinder = android_c_interface_RustBBinder_castToIBinder(
                binder_native.wrapper.as_native_mut(),
            );
            Interface::from_raw(ibinder).unwrap()
        }
    }
}
