/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::binder::{Interface, Remotable};
use crate::error::{binder_status, Error, Result};
use crate::parcel::Parcel;
use crate::proxy::SpIBinder;
use crate::sys::libbinder_bindings::*;
use crate::utils::{AsNative, Sp, String16};

use std::ops::Deref;
use std::ptr;

/// Rust wrapper around Binder remotable objects.
///
/// Implements the C++ `BBinder` class, and therefore implements the C++
/// `IBinder` interface.
#[repr(C)]
pub struct Binder<T: Remotable> {
    wrapper: Sp<android_c_interface_RustBBinder>,
    rust_object: *mut T,
}

impl<T: Remotable> Binder<T> {
    /// Create a new Binder remotable object.
    ///
    /// This moves the `rust_object` into an owned [`Box`] and Binder will
    /// manage its lifetime.
    pub fn new(rust_object: T) -> Binder<T> {
        unsafe {
            let rust_object = Box::into_raw(Box::new(rust_object));
            let descriptor: String16 = T::DESCRIPTOR.into();
            let wrapper = android_c_interface_NewRustBBinder(
                rust_object.cast(),
                descriptor.as_native(),
                Some(Self::on_transact),
                Some(Self::on_destroy),
            );
            Binder {
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
    ///        let foo: Binder<MyFoo> = Binder::new(my_foo); // class in AOSP codebase
    ///        let bar: Binder<MyBar> = Binder::new(my_bar); // custom extension class
    ///        foo.set_extension(bar.into());                // use method in Binder
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
    pub fn set_extension(&mut self, extension: &SpIBinder) {
        unsafe {
            android_c_interface_RustBBinder_setExtension(
                self.wrapper.as_native_mut(),
                extension.as_native(),
            )
        }
    }
}

impl<T: Remotable> Binder<T> {
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
            let reply = reply.as_mut().unwrap().as_mut();
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

impl<T: Remotable> Drop for Binder<T> {
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

impl<T: Remotable> Deref for Binder<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.rust_object }
    }
}

impl<B: Remotable> From<&Binder<B>> for SpIBinder {
    fn from(binder_native: &Binder<B>) -> Self {
        unsafe {
            let ibinder = android_c_interface_RustBBinder_castToIBinder(
                binder_native.wrapper.as_native(),
            );
            SpIBinder::from_raw(ibinder).unwrap()
        }
    }
}

impl<B: Remotable> From<Binder<B>> for SpIBinder {
    fn from(binder_native: Binder<B>) -> Self {
        SpIBinder::from(&binder_native)
    }
}

impl<B: Remotable> Interface for Binder<B> {
    fn new(_client: SpIBinder) -> Result<Self> {
        Err(Error::BAD_TYPE)
    }

    fn as_binder(&self) -> SpIBinder {
        SpIBinder::from(self)
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
