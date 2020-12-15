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

use crate::binder::{AsNative, Interface, InterfaceClassMethods, Remotable, TransactionCode};
use crate::error::{status_result, status_t, Result, StatusCode};
use crate::parcel::{Parcel, Serialize};
use crate::proxy::{SpIBinder, WpIBinder};
use crate::sys;

use std::convert::TryFrom;
use std::ffi::{c_void, CString};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock, Weak};

/// Rust wrapper around Binder remotable objects.
///
/// Implements the C++ `BBinder` class, and therefore implements the C++
/// `IBinder` interface.
#[repr(C)]
pub struct Binder<T: Remotable> {
    // A weak reference to the IBinder service object
    weak_ibinder: Mutex<Option<WpIBinder>>,

    // A weak reference to self
    weak_ref: RwLock<Weak<Self>>,

    rust_object: T,
}

/// # Safety
///
/// A `Binder<T>` is a pair of unique owning pointers to two values:
///   * a C++ wp<IBinder> which the C++ API guarantees can be passed between threads
///   * a Rust object which implements `Remotable`; this trait requires `Send + Sync`
///
/// Both pointers are unique (never escape the `Binder<T>` object and are not copied)
/// so we can essentially treat `Binder<T>` as a box-like containing the two objects;
/// the box-like object inherits `Send` from the two inner values, similarly
/// to how `Box<T>` is `Send` if `T` is `Send`.
unsafe impl<T: Remotable> Send for Binder<T> {}

impl<T: Remotable> Binder<T> {
    /// Create a new Binder remotable object.
    ///
    /// This moves the `rust_object` into an owned [`Box`] and Binder will
    /// manage its lifetime.
    pub fn new(rust_object: T) -> Arc<Binder<T>> {
        let binder = Arc::new(Binder {
            weak_ibinder: Mutex::new(None),
            weak_ref: RwLock::new(Weak::new()),
            rust_object,
        });
        *binder.weak_ref.write().unwrap() = Arc::downgrade(&binder);
        binder
    }

    /// Set the extension of a binder interface. This allows a downstream
    /// developer to add an extension to an interface without modifying its
    /// interface file. This should be called immediately when the object is
    /// created before it is passed to another thread.
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
    ///        # use binder::{Binder, Interface};
    ///        # type MyFoo = ();
    ///        # type MyBar = ();
    ///        # let my_foo = ();
    ///        # let my_bar = ();
    ///        let mut foo: Binder<MyFoo> = Binder::new(my_foo); // class in AOSP codebase
    ///        let bar: Binder<MyBar> = Binder::new(my_bar);     // custom extension class
    ///        foo.set_extension(&mut bar.as_binder());          // use method in Binder
    ///
    ///    Then, clients of `IFoo` can get this extension:
    ///
    ///        # use binder::{declare_binder_interface, Binder, TransactionCode, Parcel};
    ///        # trait IBar {}
    ///        # declare_binder_interface! {
    ///        #     IBar["test"] {
    ///        #         native: BnBar(on_transact),
    ///        #         proxy: BpBar,
    ///        #     }
    ///        # }
    ///        # fn on_transact(
    ///        #     service: &dyn IBar,
    ///        #     code: TransactionCode,
    ///        #     data: &Parcel,
    ///        #     reply: &mut Parcel,
    ///        # ) -> binder::Result<()> {
    ///        #     Ok(())
    ///        # }
    ///        # impl IBar for BpBar {}
    ///        # impl IBar for Binder<BnBar> {}
    ///        # fn main() -> binder::Result<()> {
    ///        # let binder = Binder::new(());
    ///        if let Some(barBinder) = binder.get_extension()? {
    ///            let bar = BpBar::new(barBinder)
    ///                .expect("Extension was not of type IBar");
    ///        } else {
    ///            // There was no extension
    ///        }
    ///        # }
    pub fn set_extension(&mut self, extension: &mut SpIBinder) -> Result<()> {
        let mut ibinder = self.as_binder().ok_or(StatusCode::DEAD_OBJECT)?;
        let status = unsafe {
            // Safety: `AIBinder_setExtension` expects two valid, mutable
            // `AIBinder` pointers. We are guaranteed that both `self` and
            // `extension` contain valid `AIBinder` pointers, because they
            // cannot be initialized without a valid
            // pointer. `AIBinder_setExtension` does not take ownership of
            // either parameter.
            sys::AIBinder_setExtension(ibinder.as_native_mut(), extension.as_native_mut())
        };
        status_result(status)
    }

    /// Retrieve the interface descriptor string for this object's Binder
    /// interface.
    pub fn get_descriptor() -> &'static str {
        T::get_descriptor()
    }
}

impl<T: Remotable> Interface for Binder<T> {
    /// Converts the local remotable object into a generic `SpIBinder`
    /// reference.
    ///
    /// The resulting `SpIBinder` will hold its own strong reference to this
    /// remotable object, which will prevent the object from being dropped while
    /// the `SpIBinder` is alive.
    fn as_binder(&self) -> Option<SpIBinder> {
        let mut weak_ibinder = self.weak_ibinder.lock().expect("Could not lock weak_ibinder");
        if let Some(weak_ibinder) = &*weak_ibinder {
            weak_ibinder.promote()
        } else {
            let class = T::get_class();
            // Self is alive, and weak_ref is a reference to self, so it is
            // trivially upgradeable
            let strong_ref = self.weak_ref.read().unwrap().upgrade().unwrap();
            let userdata = Arc::into_raw(strong_ref) as *mut c_void;
            let mut strong_ibinder = unsafe {
                // Safety: `AIBinder_new` expects a valid class pointer (which we
                // initialize via `get_class`), and an arbitrary pointer
                // argument. The caller owns the returned `AIBinder` pointer, which
                // is a strong reference to a `BBinder`. This reference should be
                // decremented via `AIBinder_decStrong` when the reference lifetime
                // ends.
                SpIBinder::from_raw(sys::AIBinder_new(class.into(), userdata))?
            };
            *weak_ibinder = Some(WpIBinder::new(&mut strong_ibinder));
            Some(strong_ibinder)
        }
    }
}

impl<T: Remotable> InterfaceClassMethods for Binder<T> {
    fn get_descriptor() -> &'static str {
        <T as Remotable>::get_descriptor()
    }

    /// Called whenever a transaction needs to be processed by a local
    /// implementation.
    ///
    /// # Safety
    ///
    /// Must be called with a non-null, valid pointer to a local `AIBinder` that
    /// contains a `T` pointer in its user data. The `data` and `reply` parcel
    /// parameters must be valid pointers to `AParcel` objects. This method does
    /// not take ownership of any of its parameters.
    ///
    /// These conditions hold when invoked by `ABBinder::onTransact`.
    unsafe extern "C" fn on_transact(
        binder: *mut sys::AIBinder,
        code: u32,
        data: *const sys::AParcel,
        reply: *mut sys::AParcel,
    ) -> status_t {
        let res = {
            let mut reply = Parcel::borrowed(reply).unwrap();
            let data = Parcel::borrowed(data as *mut sys::AParcel).unwrap();
            let object = sys::AIBinder_getUserData(binder);
            let binder: &T = &*(object as *const T);
            binder.on_transact(code, &data, &mut reply)
        };
        match res {
            Ok(()) => 0i32,
            Err(e) => e as i32,
        }
    }

    /// Called whenever an `AIBinder` object is no longer referenced and needs
    /// destroyed.
    ///
    /// # Safety
    ///
    /// Must be called with a valid pointer to a userdata object, which was
    /// created via Arc<Self>::into_raw. After this call, the pointer will be
    /// invalid and should not be dereferenced.
    unsafe extern "C" fn on_destroy(object: *mut c_void) {
        let _ = Arc::from_raw(object as *const Binder<T>);
    }

    /// Called whenever a new, local `AIBinder` object is needed of a specific
    /// class.
    ///
    /// Constructs the user data pointer that will be stored in the object,
    /// which will be a heap-allocated `T` object.
    ///
    /// # Safety
    ///
    /// Must be called with a valid pointer to a `T` object allocated via `Box`.
    unsafe extern "C" fn on_create(args: *mut c_void) -> *mut c_void {
        // We just return the argument, as it is already a pointer to the rust
        // object created by Box.
        args
    }
}

impl<T: Remotable> Deref for Binder<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.rust_object
    }
}

impl<B: Remotable> Serialize for Binder<B> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_binder(self.as_binder().as_ref())
    }
}

// This implementation is an idiomatic implementation of the C++
// `IBinder::localBinder` interface if the binder object is a Rust binder
// service.
impl<B: Remotable> TryFrom<SpIBinder> for Arc<Binder<B>> {
    type Error = StatusCode;

    fn try_from(mut ibinder: SpIBinder) -> Result<Self> {
        let class = B::get_class();
        if Some(class) != ibinder.get_class() {
            return Err(StatusCode::BAD_TYPE);
        }
        let userdata = unsafe {
            // Safety: `SpIBinder` always holds a valid pointer pointer to an
            // `AIBinder`, which we can safely pass to
            // `AIBinder_getUserData`. `ibinder` retains ownership of the
            // returned pointer.
            sys::AIBinder_getUserData(ibinder.as_native_mut()) as *const Binder<B>
        };
        if userdata.is_null() {
            return Err(StatusCode::UNEXPECTED_NULL);
        }

        // We must not take ownership of the strong reference in the user data,
        // as this should be owned by the Binder object itself. Thus we need to
        // clone and not drop the reconstituted Arc.
        let strong_ref = unsafe {
            // Safety: userdata is not null (checked above), and was created in
            // Interface::as_binder above via Arc::into_raw.
            ManuallyDrop::new(Arc::from_raw(userdata))
        };
        Ok(Arc::clone(&*strong_ref))
    }
}

/// Register a new service with the default service manager.
///
/// Registers the given binder object with the given identifier. If successful,
/// this service can then be retrieved using that identifier.
pub fn add_service(identifier: &str, mut binder: SpIBinder) -> Result<()> {
    let instance = CString::new(identifier).unwrap();
    let status = unsafe {
        // Safety: `AServiceManager_addService` expects valid `AIBinder` and C
        // string pointers. Caller retains ownership of both
        // pointers. `AServiceManager_addService` creates a new strong reference
        // and copies the string, so both pointers need only be valid until the
        // call returns.
        sys::AServiceManager_addService(binder.as_native_mut(), instance.as_ptr())
    };
    status_result(status)
}

/// Tests often create a base BBinder instance; so allowing the unit
/// type to be remotable translates nicely to Binder::new(()).
impl Remotable for () {
    fn get_descriptor() -> &'static str {
        ""
    }

    fn on_transact(
        &self,
        _code: TransactionCode,
        _data: &Parcel,
        _reply: &mut Parcel,
    ) -> Result<()> {
        Ok(())
    }

    binder_fn_get_class!(Binder::<Self>);
}

impl Interface for () {}
