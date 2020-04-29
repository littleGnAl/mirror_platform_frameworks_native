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

use crate::native::{DeathRecipient, DeathRecipientCallback, WeakDeathRecipient};
use crate::parcel::Parcel;
use crate::proxy::IInterface;
use crate::service_manager::{DumpFlags, ServiceManager};
use crate::state::{ProcessState, ThreadState};
use crate::sys::libbinder_bindings::*;
use crate::utils::{Str16, String16};
use crate::{Error, Interface, Result, Service};

use std::os::unix::io::AsRawFd;

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
pub trait Binder: Sync {
    const INTERFACE_DESCRIPTOR: &'static str;

    /// Handle and reply to a request to invoke a transaction on this object.
    ///
    /// `reply` may be [`None`] if the sender does not expect a reply.
    ///
    /// If this method return `Err(Error::UNKNOWN_TRANSACTION)`, the transaction
    /// will be forwarded to the `BBinder` base implementation of transaction
    /// handling (`BBinder::onTransact` in C++).
    fn on_transact(
        &self,
        code: TransactionCode,
        data: &Parcel,
        reply: &mut Parcel,
        flags: TransactionFlags,
    ) -> Result<()>;

    fn check_interface(&self, data: &Parcel) -> Result<()> {
        if unsafe { data.enforce_interface(&Self::INTERFACE_DESCRIPTOR.into()) } {
            Ok(())
        } else {
            Err(Error::PERMISSION_DENIED)
        }
    }
}

/// Tests often create a base BBinder instance; so allowing the unit
/// type to be remotable translates nicely to Service::new(()).
impl Binder for () {
    const INTERFACE_DESCRIPTOR: &'static str = "";

    fn on_transact(
        &self,
        _code: TransactionCode,
        _data: &Parcel,
        _reply: &mut Parcel,
        _flags: TransactionFlags,
    ) -> Result<()> {
        Ok(())
    }
}

/// Simple interface for publishing Binder services that do not require
/// initialization.
///
/// The struct will be default initialized and published directly to the service
/// manager using [`SERVICE_NAME`](BinderService::SERVICE_NAME) as the service's
/// name.
pub trait BinderService: Binder + Default {
    const SERVICE_NAME: &'static str;

    /// Publish the service to the service manager.
    fn publish(allow_isolated: bool, dump_flags: DumpFlags) -> Result<()> {
        let mut sm = ServiceManager::default();
        sm.add_service(
            Self::SERVICE_NAME,
            Service::new(Self::default()).into(),
            allow_isolated,
            dump_flags,
        )
    }

    /// Publish the service to the service manager and immediately join the
    /// binder thread pool. This function does not return.
    fn publish_and_join_thread_pool(allow_isolated: bool, dump_flags: DumpFlags) {
        let _ = Self::publish(allow_isolated, dump_flags);
        ProcessState::start_thread_pool();
        ProcessState::give_thread_pool_name();
        ThreadState::join_thread_pool(true);
    }

    /// Publish the service with default parameters.
    fn instantiate() {
        let _ = Self::publish(false, DumpFlags::PriorityDefault);
    }
}

/// Interface of binder local or remote objects.
///
/// This trait corresponds to the interface of the C++ `IBinder` class.
pub trait IBinder {
    const FIRST_CALL_TRANSACTION: TransactionCode = android_IBinder_FIRST_CALL_TRANSACTION;
    const LAST_CALL_TRANSACTION: TransactionCode = android_IBinder_LAST_CALL_TRANSACTION;
    const PING_TRANSACTION: TransactionCode = android_IBinder_PING_TRANSACTION;
    const DUMP_TRANSACTION: TransactionCode = android_IBinder_DUMP_TRANSACTION;
    const SHELL_COMMAND_TRANSACTION: TransactionCode = android_IBinder_SHELL_COMMAND_TRANSACTION;
    const INTERFACE_TRANSACTION: TransactionCode = android_IBinder_INTERFACE_TRANSACTION;
    const SYSPROPS_TRANSACTION: TransactionCode = android_IBinder_SYSPROPS_TRANSACTION;
    const EXTENSION_TRANSACTION: TransactionCode = android_IBinder_EXTENSION_TRANSACTION;
    const DEBUG_PID_TRANSACTION: TransactionCode = android_IBinder_DEBUG_PID_TRANSACTION;

    /// Corresponds to TF_ONE_WAY -- an asynchronous call.
    const FLAG_ONEWAY: TransactionFlags = android_IBinder_FLAG_ONEWAY;

    /// Private userspace flag for transaction which is being requested from a
    /// vendor context.
    const FLAG_PRIVATE_VENDOR: TransactionFlags = android_IBinder_FLAG_PRIVATE_VENDOR;

    /// Return the canonical name of the interface provided by this IBinder
    /// object.
    fn get_interface_descriptor(&self) -> &Str16;

    /// Is this object still alive?
    fn is_binder_alive(&self) -> bool;

    /// Send a ping transaction to this object
    fn ping_binder(&mut self) -> Result<()>;

    /// Dump this object to the given file handle
    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[String16]) -> Result<()>;

    /// Get a new interface that exposes additional extension functionality, if
    /// available.
    fn get_extension(&mut self) -> Result<Option<Interface>>;

    /// Perform a generic operation with the object.
    ///
    /// # Arguments
    /// * `code` - Transaction code for the operation
    /// * `data` - [`Parcel`] with input data
    /// * `reply` - Optional [`Parcel`] for reply data
    /// * `flags` - Transaction flags, e.g. marking the transaction as
    /// asynchronous ([`FLAG_ONEWAY`](IBinder::FLAG_ONEWAY))
    fn transact(
        &mut self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        flags: TransactionFlags,
    ) -> Result<()>;

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
    fn link_to_death<C: DeathRecipientCallback>(
        &mut self,
        recipient: &DeathRecipient<C>,
        cookie: Option<usize>,
        flags: TransactionFlags,
    ) -> Result<()>;

    /// Remove a previously registered death notification.
    /// The recipient will no longer be called if this object
    /// dies.
    fn unlink_to_death<C: DeathRecipientCallback>(
        &mut self,
        recipient: &WeakDeathRecipient<C>,
        cookie: Option<usize>,
        flags: TransactionFlags,
    ) -> Result<()>;

    // C++ IBinder interfaces left to be implemented:
    //
    // Work in Progress:
    // - shellCommand
    //
    // Unimplemented:
    // - attachObject
    // - findObject
    // - detachObject
    // - localBinder
    // - remoteBinder
}

pub(crate) trait IBinderInternal {
    /// Check if this object implements the interface named by `descriptor`. If
    /// it does, a corresponding [`IInterface`] is returned. Currently
    /// [`IInterface`] does not expose any useful operations, so this interface
    /// is internal-only.
    unsafe fn query_local_interface(&mut self, descriptor: &String16) -> IInterface;

    fn get_debug_pid(&mut self) -> Result<libc::pid_t>;

    fn check_subclass(&self, subclass_id: *const libc::c_void) -> bool;
}
