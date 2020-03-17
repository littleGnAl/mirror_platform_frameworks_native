//! Rust API for interacting with a remote binder service.

use crate::error::{binder_status, BinderError, BinderResult};
use crate::native::{self, TransactionCode, TransactionFlags};

/// Opaque struct that contains a native binder client handle.
///
/// This struct should generally be used only by declaring a wrapper type with
/// [`declare_binder_interface!`]
#[repr(transparent)]
pub struct BinderClient(native::Sp<native::IBinder>);

impl BinderClient {
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
}

impl Drop for BinderClient {
    fn drop(&mut self) {
        // Flush commands on this thread, just in case we have something pending
        // for this client.
        native::flush_commands();
    }
}

/// A struct that holds a binder client.
///
/// In most cases this trait should be implemented using
/// [`declare_binder_interface!`], do not implement manually unless you are sure
/// you need to.
pub trait BinderInterface {
    const DESCRIPTOR: &'static str;

    fn new(client: BinderClient) -> Self;

    fn client(&mut self) -> &mut BinderClient;

    fn get_interface_descriptor(&self) -> &'static str {
        return Self::DESCRIPTOR;
    }
}

/// Retrieve an existing service, blocking for a few seconds if it doesn't yet
/// exist.
pub fn get_service<T: BinderInterface>(name: &str) -> BinderResult<T> {
    unsafe {
        let sm = native::defaultServiceManager();
        let service = sm.getService(&name.into());
        if service.is_null() {
            Err(BinderError::NAME_NOT_FOUND)
        } else {
            Ok(T::new(BinderClient(service)))
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
        pub struct $name(BinderClient);

        impl BinderInterface for $name
        where
            $name: $interface,
        {
            const DESCRIPTOR: &'static str = $descriptor;

            fn new(client: BinderClient) -> Self {
                Self(client)
            }

            fn client(&mut self) -> &mut BinderClient {
                &mut self.0
            }
        }
    };
}
