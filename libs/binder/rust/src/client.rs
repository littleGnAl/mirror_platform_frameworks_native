//! Rust API for interacting with a remote binder service.

use crate::error::{binder_status, BinderError, BinderResult};
use crate::native::{self, Parcel, Parcelable, TransactionCode, TransactionFlags};

/// Opaque struct that contains a native binder client handle.
///
/// This struct should generally be used only by declaring a wrapper type with
/// [`declare_binder_interface!`]
#[repr(transparent)]
pub struct BinderInterface(native::Sp<native::IBinder>);

impl std::fmt::Debug for BinderInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BinderInterface")
    }
}

impl BinderInterface {
    pub const FIRST_CALL_TRANSACTION: TransactionCode = native::IBinder::FIRST_CALL_TRANSACTION;
    pub const LAST_CALL_TRANSACTION: TransactionCode = native::IBinder::LAST_CALL_TRANSACTION;
    pub const PING_TRANSACTION: TransactionCode = native::IBinder::PING_TRANSACTION;
    pub const DUMP_TRANSACTION: TransactionCode = native::IBinder::DUMP_TRANSACTION;
    pub const SHELL_COMMAND_TRANSACTION: TransactionCode =
        native::IBinder::SHELL_COMMAND_TRANSACTION;
    pub const INTERFACE_TRANSACTION: TransactionCode = native::IBinder::INTERFACE_TRANSACTION;
    pub const SYSPROPS_TRANSACTION: TransactionCode = native::IBinder::SYSPROPS_TRANSACTION;
    pub const EXTENSION_TRANSACTION: TransactionCode = native::IBinder::EXTENSION_TRANSACTION;
    pub const DEBUG_PID_TRANSACTION: TransactionCode = native::IBinder::DEBUG_PID_TRANSACTION;

    /// Corresponds to TF_ONE_WAY -- an asynchronous call.
    pub const FLAG_ONEWAY: TransactionFlags = native::IBinder::FLAG_ONEWAY;

    /// Private userspace flag for transaction which is being requested from a
    /// vendor context.
    pub const FLAG_PRIVATE_VENDOR: TransactionFlags = native::IBinder::FLAG_PRIVATE_VENDOR;

    /// Perform a binder transaction
    pub fn transact(
        &mut self,
        code: native::TransactionCode,
        data: &native::Parcel,
        reply: &mut native::Parcel,
        flags: native::TransactionFlags,
    ) -> BinderResult<()> {
        let res = unsafe { self.0.transact(code, data, reply, flags) };
        binder_status(res)
    }

    pub fn get_interface_descriptor(&mut self) -> String {
        unsafe { (*self.0.get_interface_descriptor()).to_string() }
    }
}

impl Drop for BinderInterface {
    fn drop(&mut self) {
        // Flush commands on this thread, just in case we have something pending
        // for this client.
        native::flush_commands();
    }
}

impl Parcelable for BinderInterface {
    type Deserialized = BinderInterface;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_binder(&self.0)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<BinderInterface> {
        unsafe { parcel.try_read_strong_binder().map(|binder| Self(binder)) }
    }
}

impl Parcelable for &BinderInterface {
    type Deserialized = BinderInterface;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_binder(&self.0)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<BinderInterface> {
        BinderInterface::deserialize(parcel)
    }
}

/// A struct that holds a binder client.
///
/// In most cases this trait should be implemented using
/// [`declare_binder_interface!`], do not implement manually unless you are sure
/// you need to.
pub trait BinderContainer {
    const DESCRIPTOR: &'static str;

    fn new(client: BinderInterface) -> Self;

    fn client(&mut self) -> &mut BinderInterface;

    fn get_interface_descriptor(&self) -> &'static str {
        return Self::DESCRIPTOR;
    }
}

/// Retrieve an existing service, blocking for a few seconds if it doesn't yet
/// exist.
pub fn get_service<T: BinderContainer>(name: &str) -> BinderResult<T> {
    unsafe {
        let sm = native::defaultServiceManager();
        let service = sm.getService(&name.into());
        if service.is_null() {
            Err(BinderError::NAME_NOT_FOUND)
        } else {
            Ok(T::new(BinderInterface(service)))
        }
    }
}

/// Declare a new binder client type that implements a binder interface.
///
/// # Examples
///
/// ```rust
/// declare_binder_interface!(BpServiceManager, IServiceManager, "android.os.IServiceManager");
/// ```
// TODO: make this a derive proc-macro
#[macro_export]
macro_rules! declare_binder_interface {
    ($name:ident, $interface:path, $descriptor:expr) => {
        #[repr(transparent)]
        pub struct $name(BinderInterface);

        impl BinderContainer for $name
        where
            $name: $interface,
        {
            const DESCRIPTOR: &'static str = $descriptor;

            fn new(client: BinderInterface) -> Self {
                Self(client)
            }

            fn client(&mut self) -> &mut BinderInterface {
                &mut self.0
            }
        }
    };
}
