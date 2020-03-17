use crate::binder::{Binder, IBinder};
use crate::error::{binder_status, Error, Result};
use crate::parcel::Parcel;
use crate::proxy::Interface;
use crate::sys::libbinder_bindings::*;
use crate::utils::{AsNative, Sp, Str16, String16};
use crate::{TransactionCode, TransactionFlags};

use std::convert::TryInto;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
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
    /// Create a new Binder remotable object.
    ///
    /// This moves the `rust_object` into an owned [`Box`] and Binder will
    /// manage its lifetime.
    pub fn new(rust_object: T) -> Service<T> {
        unsafe {
            let rust_object = Box::into_raw(Box::new(rust_object));
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

    /// Add an extension to this service.
    ///
    /// This allows someone to add their own additions to an interface without
    /// having to modify the original interface.
    ///
    /// # Examples
    ///
    /// For instance, imagine if we have this Binder AIDL interface definition:
    ///     interface IFoo { void doFoo(); }
    ///
    /// If an unrelated owner (perhaps in a downstream codebase) wants to make a
    /// change to the interface, they have two options:
    ///
    /// 1) Historical option that has proven to be BAD! Only the original
    ///    author of an interface should change an interface. If someone
    ///    downstream wants additional functionality, they should not ever
    ///    change the interface or use this method.
    ///    ```AIDL
    ///    BAD TO DO:  interface IFoo {                       BAD TO DO
    ///    BAD TO DO:      void doFoo();                      BAD TO DO
    ///    BAD TO DO: +    void doBar(); // adding a method   BAD TO DO
    ///    BAD TO DO:  }                                      BAD TO DO
    ///    ```
    ///
    /// 2) Option that this method enables!
    ///    Leave the original interface unchanged (do not change IFoo!).
    ///    Instead, create a new AIDL interface in a downstream package:
    ///    ```AIDL
    ///    package com.<name>; // new functionality in a new package
    ///    interface IBar { void doBar(); }
    ///    ```
    ///
    ///    When registering the interface, add:
    ///
    ///        let foo: Service<MyFoo> = Service::new(my_foo); // class in AOSP codebase
    ///        let bar: Service<MyBar> = Service::new(my_bar); // custom extension class
    ///        foo.set_extension(bar.into());                  // use method in Service
    ///
    ///    Then, clients of `IFoo` can get this extension:
    ///
    ///        let binder = ...;
    ///        if let Some(barBinder) = binder.getExtension()? {
    ///            let bar = BpBar::new(barBinder)
    ///                .expect("Extension was not of type IBar");
    ///        } else {
    ///            // There was no extension
    ///        }
    pub fn set_extension(&mut self, extension: &Interface) {
        unsafe {
            android_c_interface_RustBBinder_setExtension(
                self.wrapper.as_native_mut(),
                extension.as_native(),
            )
        }
    }
}

// It would be nice to delegate to Interface and IBinder for these
// implementations, but BBinder might override them so we need to be sure we get
// the BBinder versions.
impl<T: Binder> IBinder for Service<T> {
    // We can't use T::INTERFACE_DESCRIPTOR here because we need to return a
    // reference to a UTF16 string, not a Rust str.
    fn get_interface_descriptor(&self) -> &Str16 {
        unsafe {
            let descriptor =
                android_c_interface_RustBBinder_getInterfaceDescriptor(self.wrapper.as_native());
            Str16::from_ptr(descriptor)
        }
    }

    fn is_binder_alive(&self) -> bool {
        unsafe { android_c_interface_RustBBinder_isBinderAlive(self.wrapper.as_native()) }
    }

    fn ping_binder(&mut self) -> Result<()> {
        let status =
            unsafe { android_c_interface_RustBBinder_pingBinder(self.wrapper.as_native_mut()) };
        binder_status(status)
    }

    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[String16]) -> Result<()> {
        let args: Vec<_> = args.iter().map(|a| a.as_native()).collect();
        let status = unsafe {
            android_c_interface_RustBBinder_dump(
                self.wrapper.as_native_mut(),
                fp.as_raw_fd(),
                args.as_ptr(),
                args.len().try_into().unwrap(),
            )
        };
        binder_status(status)
    }

    fn get_extension(&mut self) -> Result<Option<Interface>> {
        let ptr =
            unsafe { android_c_interface_RustBBinder_getExtension(self.wrapper.as_native_mut()) };
        unsafe { Ok(Interface::from_raw(ptr)) }
    }

    fn transact(
        &mut self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        flags: TransactionFlags,
    ) -> Result<()> {
        let reply = reply.map(|r| r.as_native_mut()).unwrap_or(ptr::null_mut());
        let status = unsafe {
            android_c_interface_RustBBinder_transact(
                self.wrapper.as_native_mut(),
                code,
                data.as_native(),
                reply,
                flags,
            )
        };
        binder_status(status)
    }
}

impl<T: Binder> Service<T> {
    /// Called by `RustBBinder` when it receives a transaction.
    unsafe extern "C" fn on_transact(
        binder: *mut android_c_interface_RustBBinder,
        object: *mut RustObject,
        code: u32,
        data: *const android_Parcel,
        reply: *mut android_Parcel,
        flags: u32,
    ) -> android_status_t {
        let res = {
            let reply = reply.as_mut().map(|r| r.as_mut());
            let data = data.as_ref().unwrap().as_ref();
            let binder: &T = &*(object as *const T);
            binder.on_transact(code, data, reply, flags)
        };
        match res {
            Ok(()) => 0i32,
            Err(Error::UNKNOWN_TRANSACTION) => {
                // Forward to `BBinder::onTransact` if we didn't understand this
                // transaction.
                android_BBinder_onTransact(binder.cast(), code, data, reply, flags)
            }
            Err(e) => e as i32,
        }
    }

    /// Called by `RustBBinder` when it is being destroyed.
    ///
    /// Signals that the lifetime of our [`RustObject`] must end.
    unsafe extern "C" fn on_destroy(object: *mut RustObject) {
        ptr::drop_in_place(object as *mut T)
    }

    /// Write this Binder to a [`Parcel`].
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
    // This causes C++ to decrease the strong ref count of the RustBBinder
    // object. We specifically do not drop the `rust_object` here. When C++
    // actually destroys RustBBinder, it calls `on_destroy` and we can drop
    // `rust_object` then.
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

impl<B: Binder> From<Service<B>> for Interface {
    fn from(mut binder_native: Service<B>) -> Self {
        (&mut binder_native).into()
    }
}

impl<B: Binder> From<&mut Service<B>> for Interface {
    fn from(binder_native: &mut Service<B>) -> Self {
        unsafe {
            let ibinder = android_c_interface_RustBBinder_castToIBinder(
                binder_native.wrapper.as_native_mut(),
            );
            Interface::from_raw(ibinder).unwrap()
        }
    }
}

unsafe impl AsNative<android_c_interface_RustBBinder> for Sp<android_c_interface_RustBBinder> {
    fn as_native(&self) -> *const android_c_interface_RustBBinder {
        if self.0.is_null() {
            ptr::null()
        } else {
            unsafe { android_c_interface_Sp_getRustBBinder(self.0) }
        }
    }

    fn as_native_mut(&mut self) -> *mut android_c_interface_RustBBinder {
        if self.0.is_null() {
            ptr::null_mut()
        } else {
            unsafe { android_c_interface_Sp_getRustBBinder(self.0) }
        }
    }
}
