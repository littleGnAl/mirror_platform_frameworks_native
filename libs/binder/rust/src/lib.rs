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

//! Rust interface to Android `libbinder`
//!
//! # Example
//!
//! ```
//! use binder::{Remotable, Parcel, SpIBinder};
//!
//! pub trait ITest {
//!     // DESCRIPTOR is required for Binder Interfaces
//!     const DESCRIPTOR: &'static str = "android.os.ITest";
//!
//!     fn test(&mut self) -> binder::Result<String>;
//! }
//!
//! // Local implementation of the ITest remotable interface.
//! struct TestService;
//!
//! impl TestService {
//!     fn test() -> &'static str {
//!         "testing service"
//!     }
//! }
//!
//! impl Remotable for TestService {
//!     const DESCRIPTOR: &'static str = <Self as ITest>::INTERFACE_DESCRIPTOR;
//!
//!     fn on_transact(
//!         &self,
//!         _code: TransactionCode,
//!         _data: &Parcel,
//!         reply: Option<&mut Parcel>,
//!         _flags: TransactionFlags,
//!     ) -> binder::Result<()> {
//!         reply.unwrap().write_utf8_as_utf16(TestService::test())?;
//!         Ok(())
//!     }
//! }
//!
//! impl ITest for TestService {
//!     fn test(&mut self) -> binder::Result<String> {
//!         Ok(TestService::test().to_string())
//!     }
//! }
//!
//! // Creates a new proxy, BpTest, that will wrap a remote object
//! // implementing ITest over binder.
//! declare_binder_proxy!(BpTest: ITest);
//!
//! impl ITest for BpTest {
//!     fn test(&mut self) -> binder::Result<String> {
//!         let mut reply = Parcel::new();
//!         self.0.transact(
//!             SpIBinder::FIRST_CALL_TRANSACTION,
//!             &Parcel::new(),
//!             Some(&mut reply),
//!             0,
//!         )?;
//!         Ok(reply.read_string16().unwrap().to_string())
//!     }
//! }
//! ```

#[macro_use]
mod utils;
#[macro_use]
mod proxy;

mod binder;
mod error;
mod native;
mod state;
mod sys;

pub mod interfaces;
pub mod parcel;
pub mod service_manager;

pub use binder::{BinderService, IBinder, Interface, Remotable, TransactionCode, TransactionFlags};
pub use error::binder_status;
pub use error::{status_t, Error, Result};
pub use native::Binder;
pub use parcel::Parcel;
pub use proxy::get_service;
pub use proxy::SpIBinder;
pub use state::{ProcessState, ThreadState};
pub use sys::binder_size_t as size_t;
pub use utils::{Str16, Str8, String16, String8, UniqueFd};

/// Re-exports of core structures, prefixed with `Binder`.
///
/// This module renames binder exports so they be glob-imported without
/// conflicting with standard structures. Import the prelude with:
/// ```rust
/// use binder::prelude::*;
/// ```
pub mod prelude {
    pub use super::Binder;
    pub use super::Error as BinderError;
    pub use super::IBinder;
    pub use super::Interface as BinderInterface;
    pub use super::Remotable as BinderRemotable;
    pub use super::Result as BinderResult;
}
