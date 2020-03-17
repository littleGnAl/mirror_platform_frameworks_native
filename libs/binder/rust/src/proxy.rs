//! Rust API for interacting with a remote binder service.

use crate::error::{binder_status, Error, Result};
use crate::parcel::{Parcel, Parcelable};
use crate::service_manager::defaultServiceManager;
use crate::sys::libbinder_bindings::*;
use crate::utils::{AsNative, Sp, Str16, String16};

use std::ptr;

/// Binder action to perform.
///
/// This must be a number between [`Interface::FIRST_CALL_TRANSACTION`] and
/// [`Interface::LAST_CALL_TRANSACTION`]. Transaction codes for a binder
/// interface are generally enumerated in the interface's [`Handle`] struct.
pub type TransactionCode = u32;

/// Additional operation flags.
///
/// Can be either 0 for a normal RPC, or [`Interface::FLAG_ONEWAY`] for a
/// one-way RPC.
pub type TransactionFlags = u32;

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
    }
}

/// # Safety
///
/// An IBinder is a handle to a C++ IBinder, which is thread-safe
unsafe impl Send for Interface {}

impl Interface {
    pub const FIRST_CALL_TRANSACTION: TransactionCode = android_IBinder_FIRST_CALL_TRANSACTION;
    pub const LAST_CALL_TRANSACTION: TransactionCode = android_IBinder_LAST_CALL_TRANSACTION;
    pub const PING_TRANSACTION: TransactionCode = android_IBinder_PING_TRANSACTION;
    pub const DUMP_TRANSACTION: TransactionCode = android_IBinder_DUMP_TRANSACTION;
    pub const SHELL_COMMAND_TRANSACTION: TransactionCode =
        android_IBinder_SHELL_COMMAND_TRANSACTION;
    pub const INTERFACE_TRANSACTION: TransactionCode = android_IBinder_INTERFACE_TRANSACTION;
    pub const SYSPROPS_TRANSACTION: TransactionCode = android_IBinder_SYSPROPS_TRANSACTION;
    pub const EXTENSION_TRANSACTION: TransactionCode = android_IBinder_EXTENSION_TRANSACTION;
    pub const DEBUG_PID_TRANSACTION: TransactionCode = android_IBinder_DEBUG_PID_TRANSACTION;

    /// Corresponds to TF_ONE_WAY -- an asynchronous call.
    pub const FLAG_ONEWAY: TransactionFlags = android_IBinder_FLAG_ONEWAY;

    /// Private userspace flag for transaction which is being requested from a
    /// vendor context.
    pub const FLAG_PRIVATE_VENDOR: TransactionFlags = android_IBinder_FLAG_PRIVATE_VENDOR;

    /// Perform a binder transaction
    // TODO: Should we return a reply in the Result instead of passing in
    // an out param?
    pub fn transact(
        &mut self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        flags: TransactionFlags,
    ) -> Result<()> {
        let reply = reply.map(|r| r.as_native_mut()).unwrap_or(ptr::null_mut());
        let status = unsafe {
            android_c_interface_IBinder_transact(
                self.0.as_native_mut(),
                code,
                data.as_native(),
                reply,
                flags,
            )
        };
        binder_status(status)
    }

    pub fn get_interface_descriptor(&mut self) -> &Str16 {
        unsafe {
            let descriptor =
                android_c_interface_IBinder_getInterfaceDescriptor(self.0.as_native_mut());
            Str16::from_ptr(descriptor)
        }
    }

    pub fn ping_binder(&mut self) -> Result<()> {
        let status = unsafe { android_c_interface_IBinder_pingBinder(self.0.as_native_mut()) };
        binder_status(status)
    }

    pub fn get_extension(&mut self) -> Result<Option<Interface>> {
        let mut out = ptr::null_mut();
        let status =
            unsafe { android_c_interface_IBinder_getExtension(self.0.as_native_mut(), &mut out) };
        let ibinder = unsafe { Interface::from_raw(out) };

        binder_status(status).map(|_| ibinder)
    }

    // TODO: Implement virtual method wrappers for the rest of IBinder
}

impl Parcelable for Interface {
    type Deserialized = Interface;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        let status =
            unsafe { android_Parcel_writeStrongBinder(parcel.as_native_mut(), self.0.as_native()) };
        binder_status(status)
    }

    fn deserialize(parcel: &Parcel) -> Result<Interface> {
        let mut sp = ptr::null_mut();
        let status =
            unsafe { android_c_interface_Parcel_readStrongBinder(parcel.as_native(), &mut sp) };
        let ibinder = unsafe { Interface::from_raw(sp) };

        binder_status(status).and_then(|_| ibinder.ok_or(Error::UNEXPECTED_NULL))
    }
}

wrap_sp! {
    /// Rust wrapper around Binder interfaces. Encapsulates the C++ IInterface
    /// class.
    pub struct IInterface(Sp<android_IInterface>) {
        getter: android_c_interface_Sp_getIInterface,
        destructor: android_c_interface_Sp_DropIInterface,
        clone: android_c_interface_Sp_CloneIInterface,
    }
}

/// A struct that holds a binder client.
///
/// In most cases this trait should be implemented using
/// [`declare_binder_interface!`]. Do not implement manually unless you are sure
/// you need to.
pub trait Handle {
    const DESCRIPTOR: &'static str;

    fn new(client: Interface) -> Self;

    fn client(&mut self) -> &mut Interface;

    fn get_interface_descriptor(&self) -> &'static str {
        return Self::DESCRIPTOR;
    }
}

/// Retrieve an existing service, blocking for a few seconds if it doesn't yet
/// exist.
pub fn get_service<T: Handle>(name: &str) -> Result<T> {
    unsafe {
        let sm = defaultServiceManager().ok_or(Error::NAME_NOT_FOUND)?;
        match sm.getService(&name.into()) {
            Some(service) => Ok(T::new(service)),
            None => Err(Error::NAME_NOT_FOUND),
        }
    }
}

/// Declare a handle type for a binder interface.
///
/// Creates a declaration of a [`Handle`] type called `$name` which holds a
/// handle to a (potentially) remote binder object implementing a particular
/// interface (`$interface`). `$descriptor` must be the interface descriptor for
/// this binder interface, which will be embedded in the new handle type.
///
/// # Examples
///
/// The following example declares the handle type `BpServiceManager` (short for
/// Binder Proxy ServiceManager). `BpServiceManager` will hold a handle to a
/// remote object that implements the `IServiceManager` trait. This handle has
/// the fully-qualified descriptor "android.os.IServiceManager".
///
/// ```rust
/// declare_binder_interface!(BpServiceManager, IServiceManager, "android.os.IServiceManager");
/// ```
// TODO: make this a derive proc-macro
#[macro_export]
macro_rules! declare_binder_interface {
    ($name:ident, $interface:path, $descriptor:expr) => {
        declare_binder_interface!(@doc
            $name,
            $interface,
            $descriptor,
            concat!("A binder [`Handle`]($crate::Handle) that holds an [`", stringify!($interface), "`] remote interface.")
        );
    };

    (@doc $name:ident, $interface:path, $descriptor:expr, $doc:expr) => {
        #[doc = $doc]
        #[repr(transparent)]
        pub struct $name($crate::Interface);

        impl $crate::Handle for $name
        where
            $name: $interface,
        {
            const DESCRIPTOR: &'static str = $descriptor;

            fn new(client: $crate::Interface) -> Self {
                Self(client)
            }

            fn client(&mut self) -> &mut $crate::Interface {
                &mut self.0
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Internal APIs

#[allow(unused)]
impl Interface {
    pub(crate) unsafe fn query_local_interface(&mut self, descriptor: &String16) -> IInterface {
        IInterface::from_raw(android_c_interface_IBinder_queryLocalInterface(
            self.0.as_native_mut(),
            descriptor.as_native(),
        ))
        .unwrap()
    }

    pub(crate) fn is_null(&self) -> bool {
        let ptr: *const android_IBinder = self.0.as_native();
        ptr.is_null()
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
