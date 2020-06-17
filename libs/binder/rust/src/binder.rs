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

//! Trait definitions for binder objects

use crate::error::Result;
use crate::parcel::Parcel;
use crate::proxy::{DeathRecipient, SpIBinder};
use crate::sys;

use std::ffi::{c_void, CString};
use std::os::unix::io::AsRawFd;
use std::ptr;

/// Binder action to perform.
///
/// This must be a number between [`IBinder::FIRST_CALL_TRANSACTION`] and
/// [`IBinder::LAST_CALL_TRANSACTION`]. Transaction codes for a binder interface
/// are generally enumerated in the interface's [`Handle`](crate::proxy::Handle)
/// struct.
pub type TransactionCode = u32;

/// Additional operation flags.
///
/// Can be either 0 for a normal RPC, or [`IBinder::FLAG_ONEWAY`] for a
/// one-way RPC.
pub type TransactionFlags = u32;

/// A struct that is remotable via Binder.
///
/// This is a low-level interface that should normally be automatically
/// generated from AIDL.
pub trait Remotable: Sync {
    const DESCRIPTOR: &'static str;

    /// Handle and reply to a request to invoke a transaction on this object.
    ///
    /// `reply` may be [`None`] if the sender does not expect a reply.
    fn on_transact(&self, code: TransactionCode, data: &Parcel, reply: &mut Parcel) -> Result<()>;

    /// Retrieve the class of this remote object.
    ///
    /// This method should only be implemented by the macro
    /// [`binder_fn_get_class!`], but must be located in the object that
    /// implements the interface.
    fn get_class() -> InterfaceClass;
}

/// Interface of binder local or remote objects.
///
/// This trait corresponds to the interface of the C++ `IBinder` class.
pub trait IBinder {
    const FIRST_CALL_TRANSACTION: TransactionCode = sys::FIRST_CALL_TRANSACTION;
    const LAST_CALL_TRANSACTION: TransactionCode = sys::LAST_CALL_TRANSACTION;

    /// Corresponds to TF_ONE_WAY -- an asynchronous call.
    const FLAG_ONEWAY: TransactionFlags = sys::FLAG_ONEWAY;

    /// Is this object still alive?
    fn is_binder_alive(&self) -> bool;

    /// Send a ping transaction to this object
    fn ping_binder(&mut self) -> Result<()>;

    /// Dump this object to the given file handle
    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[&str]) -> Result<()>;

    /// Get a new interface that exposes additional extension functionality, if
    /// available.
    fn get_extension(&mut self) -> Result<Option<SpIBinder>>;

    /// Perform a generic operation with the object.
    ///
    /// # Arguments
    /// * `code` - Transaction code for the operation
    /// * `data` - [`Parcel`] with input data
    /// * `reply` - Optional [`Parcel`] for reply data
    /// * `flags` - Transaction flags, e.g. marking the transaction as
    /// asynchronous ([`FLAG_ONEWAY`](IBinder::FLAG_ONEWAY))
    fn transact<F: FnOnce(&mut Parcel) -> Result<()>>(
        &self,
        code: TransactionCode,
        flags: TransactionFlags,
        input_callback: F,
    ) -> Result<Parcel>;

    /// Register the recipient for a notification if this binder
    /// goes away. If this binder object unexpectedly goes away
    /// (typically because its hosting process has been killed),
    /// then DeathRecipient::binder_died() will be called with a reference
    /// to this.
    ///
    /// You will only receive death notifications for remote binders,
    /// as local binders by definition can't die without you dying as well.
    /// Trying to use this function on a local binder will result in an
    /// INVALID_OPERATION code being returned and nothing happening.
    ///
    /// This link always holds a weak reference to its recipient.
    ///
    /// You will only receive a weak reference to the dead
    /// binder. You should not try to promote this to a strong reference.
    /// (Nor should you need to, as there is nothing useful you can
    /// directly do with it now that it has passed on.)
    fn link_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()>;

    /// Remove a previously registered death notification.
    /// The recipient will no longer be called if this object
    /// dies.
    fn unlink_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()>;

    // C++ IBinder interfaces left to be implemented:
    //
    // Unimplemented:
    // - attachObject
    // - findObject
    // - detachObject
}

/// Interface for objects that can be converted to and from [`SpIBinder`] objects.
///
/// Corresponds to the C++ `IInterface` class. We would like to require this
/// trait for all Binder remote interfaces (i.e. `IFoo` traits), but doing so
/// would make these traits not valid to make into trait objects, which is
/// essential. Instead, users should implement this trait on `BnFoo` and
/// `BpFoo`, the local and proxy objects implementing `IFoo`, instead.
pub trait Interface: Sized {
    const DESCRIPTOR: &'static str;

    /// Create a new interface from the given proxy, if it matches the expected
    /// type of this interface.
    fn new(client: SpIBinder) -> Result<Self>;

    /// Retrieve an [`SpIBinder`] from this interface.
    fn as_binder(&self) -> SpIBinder;

    /// Retrieve the class of this remote object.
    ///
    /// This method should only be implemented by the macro
    /// [`binder_fn_get_class!`], but must be located in the object that
    /// implements the interface.
    fn get_class() -> InterfaceClass;
}

/// # Safety
///
/// This is a convenience method that wraps `AsNative` for `SpIBinder` to allow
/// invocation of `IBinder` methods directly from `Interface` objects. It shares
/// the same safety as the implementation for `SpIBinder`.
unsafe impl<T: Interface> AsNative<sys::AIBinder> for T {
    fn as_native(&self) -> *const sys::AIBinder {
        self.as_binder().as_native()
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder {
        self.as_binder().as_native_mut()
    }
}

/// Opaque reference to the type of a Binder interface.
///
/// This object encapsulates the Binder interface descriptor string, along with
/// the binder transaction callback, if the class describes a local service.
///
/// A Binder remotable object may only have a single interface class, and any
/// given object can only be associated with one class. Two objects with
/// different classes are incompatible, even if both classes have the same
/// interface descriptor.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct InterfaceClass(*const sys::AIBinder_Class);

impl InterfaceClass {
    /// Get a Binder NDK `AIBinder_Class` pointer for this object type.
    ///
    /// Note: the returned pointer will not be constant. Calling this method
    /// multiple times for the same type will result in distinct class
    /// pointers. A static getter should be implemented using
    /// [`binder_fn_get_class!`].
    pub fn new<I: InterfaceClassMethods>() -> InterfaceClass {
        let descriptor = CString::new(I::get_descriptor()).unwrap();
        let ptr = unsafe {
            // Safety: `AIBinder_Class_define` expects a valid C string, and
            // three valid callback functions, all non-null pointers. The C
            // string is copied and need not be valid for longer than the call,
            // so we can drop it after the call.
            sys::AIBinder_Class_define(
                descriptor.as_ptr(),
                Some(I::on_create),
                Some(I::on_destroy),
                Some(I::on_transact),
            )
        };
        InterfaceClass(ptr)
    }

    /// Construct an `InterfaceClass` out of a raw, non-null `AIBinder_Class`
    /// pointer.
    ///
    /// # Safety
    ///
    /// This function is safe iff `ptr` is a valid, non-null pointer to an
    /// `AIBinder_Class`.
    pub(crate) unsafe fn from_ptr(ptr: *const sys::AIBinder_Class) -> InterfaceClass {
        InterfaceClass(ptr)
    }
}

impl From<InterfaceClass> for *const sys::AIBinder_Class {
    fn from(class: InterfaceClass) -> *const sys::AIBinder_Class {
        class.0
    }
}

/// Create a function implementing a static getter for an interface class.
///
/// Each binder interface (i.e. local [`Remotable`] service or remote proxy
/// [`Interface`]) must have global, static class that uniquely identifies
/// it. This macro implements an [`InterfaceClass`] getter to simplify these
/// implementations.
///
/// The type of a structure that implements [`InterfaceClassMethods`] must be
/// passed to this macro. For local services, this should be `Binder<Self>`
/// since [`Binder`] implements [`InterfaceClassMethods`].
///
/// # Examples
///
/// When implementing a local [`Remotable`] service `ExampleService`, the
/// `get_class` method is required in the [`Remotable`] impl block. This macro
/// should be used as follows to implement this functionality:
///
/// ```rust
/// impl Remotable for ExampleService {
///     const DESCRIPTOR: &'static str = "android.os.IExampleInterface";
///
///     fn on_transact(
///         &self,
///         code: TransactionCode,
///         data: &Parcel,
///         reply: &mut Parcel,
///     ) -> Result<()> {
///         // ...
///     }
///
///     binder_fn_get_class!(Binder<Self>);
/// }
/// ```
#[macro_export]
macro_rules! binder_fn_get_class {
    ($class:ty) => {
        fn get_class() -> $crate::InterfaceClass {
            static CLASS_INIT: std::sync::Once = std::sync::Once::new();
            static mut CLASS: Option<$crate::InterfaceClass> = None;

            CLASS_INIT.call_once(|| unsafe {
                CLASS = Some($crate::InterfaceClass::new::<$class>());
            });
            unsafe { CLASS.unwrap() }
        }
    };
}

pub trait InterfaceClassMethods {
    /// Get the interface descriptor string for this object type.
    fn get_descriptor() -> &'static str;

    /// Called during construction of a new `AIBinder` object of this interface
    /// class.
    ///
    /// The opaque pointer parameter will be the parameter provided to
    /// `AIBinder_new`. Returns an opaque userdata to be associated with the new
    /// `AIBinder` object.
    ///
    /// # Safety
    ///
    /// Callback called from C++. The parameter argument provided to
    /// `AIBinder_new` must match the type expected here. The `AIBinder` object
    /// will take ownership of the returned pointer, which it will free via
    /// `on_destroy`.
    unsafe extern "C" fn on_create(args: *mut c_void) -> *mut c_void;

    /// Called when a transaction needs to be processed by the local service
    /// implementation.
    ///
    /// # Safety
    ///
    /// Callback called from C++. The `binder` parameter must be a valid pointer
    /// to a binder object of this class with userdata initialized via this
    /// class's `on_create`. The parcel parameters must be valid pointers to
    /// parcel objects.
    unsafe extern "C" fn on_transact(
        binder: *mut sys::AIBinder,
        code: u32,
        data: *const sys::AParcel,
        reply: *mut sys::AParcel,
    ) -> sys::status_t;

    /// Called whenever an `AIBinder` object is no longer referenced and needs
    /// to be destroyed.
    ///
    /// # Safety
    ///
    /// Callback called from C++. The opaque pointer parameter must be the value
    /// returned by `on_create` for this class. This function takes ownership of
    /// the provided pointer and destroys it.
    unsafe extern "C" fn on_destroy(object: *mut c_void);
}

// This interface class implementation is only for remote, proxy objects. This
// implementation sets the descriptor for the class, but provides callback
// methods that cannot be used to instantiate a local service. The callbacks
// will panic if this class is used to create a new local service.
impl<I: Interface> InterfaceClassMethods for I {
    fn get_descriptor() -> &'static str {
        Self::DESCRIPTOR
    }

    /// # Safety
    ///
    /// Always panics, do not call.
    unsafe extern "C" fn on_create(_: *mut c_void) -> *mut c_void {
        unreachable!("Cannot instantiate an interface without a service");
    }

    /// # Safety
    ///
    /// Always panics, do not call.
    unsafe extern "C" fn on_destroy(_: *mut c_void) {
        unreachable!("Cannot instantiate an interface without a service");
    }

    /// # Safety
    ///
    /// Always panics, do not call.
    unsafe extern "C" fn on_transact(
        _: *mut sys::AIBinder,
        _: u32,
        _: *const sys::AParcel,
        _: *mut sys::AParcel,
    ) -> sys::status_t {
        unreachable!("Cannot instantiate an interface without a service");
    }
}

/// Interface for transforming a generic SpIBinder into a specific remote
/// interface trait.
///
/// # Example
///
/// For Binder interface `IFoo`, the following implementation should be made:
/// ```rust
/// impl IntoInterface<dyn IFoo> for SpIBinder {
///     // ...
/// }
/// ```
pub trait IntoInterface<I: ?Sized> {
    fn into_interface(self) -> Result<Box<I>>;
}

/// Trait for transparent Rust wrappers around android C++ native types.
///
/// The pointer return by this trait's methods should be immediately passed to
/// C++ and not stored by Rust. The pointer is valid only as long as the
/// underlying C++ object is alive, so users must be careful to take this into
/// account, as Rust cannot enforce this.
///
/// # Safety
///
/// For this trait to be a correct implementation, `T` must be a valid android
/// C++ type. Since we cannot constrain this via the type system, this trait is
/// marked as unsafe.
pub unsafe trait AsNative<T> {
    /// Return a pointer to the native version of `self`
    fn as_native(&self) -> *const T;

    /// Return a mutable pointer to the native version of `self`
    fn as_native_mut(&mut self) -> *mut T;
}

unsafe impl<T, V: AsNative<T>> AsNative<T> for Option<V> {
    fn as_native(&self) -> *const T {
        self.as_ref().map_or(ptr::null(), |v| v.as_native())
    }

    fn as_native_mut(&mut self) -> *mut T {
        self.as_mut().map_or(ptr::null_mut(), |v| v.as_native_mut())
    }
}
