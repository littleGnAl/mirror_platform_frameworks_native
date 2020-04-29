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

//! Rust API for interacting with a remote binder service.

use crate::binder::{IBinder, IBinderInternal, TransactionCode, TransactionFlags};
use crate::error::{binder_status, Error, Result};
use crate::native::{DeathRecipient, DeathRecipientCallback, WeakDeathRecipient};
use crate::parcel::{Parcel, Parcelable};
use crate::service_manager::ServiceManager;
use crate::sys::libbinder_bindings::*;
use crate::utils::{AsNative, Sp, Str16, String16, Wp};

use std::convert::TryInto;
use std::os::unix::io::AsRawFd;
use std::ptr;

wrap_sp! {
    /// Rust wrapper around Binder remote objects.
    ///
    /// This struct encapsulates the C++ `IBinder` class. However, this wrapper
    /// is untyped, so properly typed versions implementing a particular binder
    /// interface should be crated with [`declare_binder_interface!`].
    pub struct Interface(Sp<android_IBinder>) {
        getter: android_c_interface_Sp_getIBinder,
        destructor: android_c_interface_Sp_DropIBinder,
        clone: android_c_interface_Sp_CloneIBinder,
        strong_count: android_c_interface_Sp_StrongCountIBinder,
    }
}

/// # Safety
///
/// An `Interface` is a handle to a C++ IBinder, which is thread-safe
unsafe impl Send for Interface {}

impl Interface {
    pub fn is_null(&self) -> bool {
        let ptr: *const android_IBinder = self.0.as_native();
        ptr.is_null()
    }
}

impl<T: AsNative<android_IBinder>> IBinder for T {
    /// Perform a binder transaction
    fn transact(
        &mut self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        flags: TransactionFlags,
    ) -> Result<()> {
        let reply = reply.map(|r| r.as_native_mut()).unwrap_or(ptr::null_mut());
        let status = unsafe {
            android_c_interface_IBinder_transact(
                self.as_native_mut(),
                code,
                data.as_native(),
                reply,
                flags,
            )
        };
        binder_status(status)
    }

    fn get_interface_descriptor(&self) -> &Str16 {
        unsafe {
            let descriptor = android_c_interface_IBinder_getInterfaceDescriptor(self.as_native());
            Str16::from_ptr(descriptor)
        }
    }

    fn is_binder_alive(&self) -> bool {
        unsafe { android_c_interface_IBinder_isBinderAlive(self.as_native()) }
    }

    fn ping_binder(&mut self) -> Result<()> {
        let status = unsafe { android_c_interface_IBinder_pingBinder(self.as_native_mut()) };
        binder_status(status)
    }

    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[String16]) -> Result<()> {
        let args: Vec<_> = args.iter().map(|a| a.as_native()).collect();
        let status = unsafe {
            android_c_interface_IBinder_dump(
                self.as_native_mut(),
                fp.as_raw_fd(),
                args.as_ptr(),
                args.len().try_into().unwrap(),
            )
        };
        binder_status(status)
    }

    fn get_extension(&mut self) -> Result<Option<Interface>> {
        let mut out = ptr::null_mut();
        let status =
            unsafe { android_c_interface_IBinder_getExtension(self.as_native_mut(), &mut out) };
        let ibinder = unsafe { Interface::from_raw(out) };

        binder_status(status).map(|_| ibinder)
    }

    fn link_to_death<C: DeathRecipientCallback>(
        &mut self,
        recipient: &DeathRecipient<C>,
        cookie: Option<usize>,
        flags: TransactionFlags,
    ) -> Result<()> {
        binder_status(unsafe {
            android_c_interface_IBinder_linkToDeath(
                self.as_native_mut(),
                recipient.as_native(),
                cookie
                    .map(|i| i as *mut libc::c_void)
                    .unwrap_or(ptr::null_mut()),
                flags,
            )
        })
    }

    fn unlink_to_death<C: DeathRecipientCallback>(
        &mut self,
        recipient: &WeakDeathRecipient<C>,
        cookie: Option<usize>,
        flags: TransactionFlags,
    ) -> Result<()> {
        binder_status(unsafe {
            android_c_interface_IBinder_unlinkToDeath(
                self.as_native_mut(),
                recipient.as_native(),
                cookie
                    .map(|i| i as *mut libc::c_void)
                    .unwrap_or(ptr::null_mut()),
                flags,
                ptr::null_mut(),
            )
        })
    }
}

impl Parcelable for Interface {
    type Deserialized = Interface;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_binder(self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Interface> {
        let ibinder = unsafe { parcel.read_strong_binder()? };
        ibinder.ok_or(Error::UNEXPECTED_NULL)
    }
}

wrap_sp! {
    /// Rust wrapper around Binder interfaces. Encapsulates the C++ IInterface
    /// class.
    pub(crate) struct IInterface(Sp<android_IInterface>) {
        getter: android_c_interface_Sp_getIInterface,
        destructor: android_c_interface_Sp_DropIInterface,
        clone: android_c_interface_Sp_CloneIInterface,
    }
}

/// A struct that holds a binder client of a particular interface.
///
/// In most cases this trait should be implemented using
/// [`declare_binder_interface!`]. Do not implement manually unless you are sure
/// you need to.
pub trait Handle: Sized {
    /// Create a new handle from the given interface, if it matches the expected
    /// type of this handle.
    fn new(client: Interface) -> Result<Self>;

    /// Retrieve the [`Interface`] from this handle.
    fn remote(&self) -> &Interface;

    /// Retrieve a mutable [`Interface`] from this handle.
    fn remote_mut(&mut self) -> &mut Interface;
}

unsafe impl<H: Handle> AsNative<android_IBinder> for H {
    fn as_native(&self) -> *const android_IBinder {
        self.remote().as_native()
    }

    fn as_native_mut(&mut self) -> *mut android_IBinder {
        self.remote_mut().as_native_mut()
    }
}

/// Retrieve an existing service, blocking for a few seconds if it doesn't yet
/// exist.
pub fn get_service<T: Handle>(name: &str) -> Result<T> {
    let sm = ServiceManager::default();
    match sm.get_service(name) {
        Some(service) => T::new(service),
        None => Err(Error::NAME_NOT_FOUND),
    }
}

/// Declare a handle type for a binder interface.
///
/// Creates a declaration of a [`Handle`] type called `$name` which holds a
/// handle to a (potentially) remote binder object implementing a particular
/// interface (`$interface`). The interface must contain an associated constant
/// static string `INTERFACE_DESCRIPTOR` which is the interface descriptor for
/// this binder interface.
///
/// # Examples
///
/// The following example declares the handle type `BpServiceManager` (short for
/// Binder Proxy ServiceManager). `BpServiceManager` will hold a handle to a
/// remote object that implements the `IServiceManager` trait.
///
/// ```rust
/// pub trait IServiceManager {
///    const INTERFACE_DESCRIPTOR: &'static str = "android.os.IServiceManager";
///
///    // remote methods...
/// }
///
/// declare_binder_interface!(BpServiceManager: IServiceManager);
/// ```
// TODO: make this a derive proc-macro
#[macro_export]
macro_rules! declare_binder_interface {
    ($name:ident: $interface:path) => {
        declare_binder_interface!(@doc
            $name,
            $interface,
            concat!("A binder [`Handle`]($crate::Handle) that holds an [`", stringify!($interface), "`] remote interface.")
        );
    };

    (@doc $name:ident, $interface:path, $doc:expr) => {
        #[doc = $doc]
        #[repr(transparent)]
        pub struct $name($crate::Interface);

        impl $crate::Handle for $name
        where
            $name: $interface,
        {
            fn new(client: $crate::Interface) -> $crate::Result<Self> {
                if client.get_interface_descriptor().to_string() == <Self as $interface>::INTERFACE_DESCRIPTOR {
                    Ok(Self(client))
                } else {
                    Err($crate::Error::BAD_TYPE)
                }
            }

            fn remote(&self) -> & $crate::Interface {
                &self.0
            }

            fn remote_mut(&mut self) -> &mut $crate::Interface {
                &mut self.0
            }
        }
    };
}

wrap_wp! {
    /// Rust wrapper around a weak reference to a Binder remote objects.
    pub struct WeakInterface(Wp<android_IBinder>) {
        clone: android_c_interface_Wp_CloneIBinder,
        destructor: android_c_interface_Wp_DropIBinder,
        promote: (Interface, android_c_interface_Wp_PromoteIBinder),
    }
}

// ---------------------------------------------------------------------------
// Internal APIs

impl IBinderInternal for Interface {
    unsafe fn query_local_interface(&mut self, descriptor: &String16) -> IInterface {
        IInterface::from_raw(android_c_interface_IBinder_queryLocalInterface(
            self.0.as_native_mut(),
            descriptor.as_native(),
        ))
        .unwrap()
    }

    fn get_debug_pid(&mut self) -> Result<libc::pid_t> {
        let mut pid: libc::pid_t = 0;
        let status =
            unsafe { android_c_interface_IBinder_getDebugPid(self.0.as_native_mut(), &mut pid) };
        binder_status(status).map(|_| pid)
    }

    fn check_subclass(&self, subclass_id: *const libc::c_void) -> bool {
        unsafe { android_c_interface_IBinder_checkSubclass(self.0.as_native(), subclass_id) }
    }
}

unsafe impl AsNative<android_sp<android_IBinder>> for Interface {
    fn as_native(&self) -> *const android_sp<android_IBinder> {
        self.0.as_native()
    }

    fn as_native_mut(&mut self) -> *mut android_sp<android_IBinder> {
        self.0.as_native_mut()
    }
}
