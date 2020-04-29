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

pub use binder::{Binder, BinderService, IBinder, TransactionCode, TransactionFlags};
pub use error::binder_status;
pub use error::{status_t, Error, Result};
pub use native::{DeathRecipient, DeathRecipientCallback, Service};
pub use proxy::get_service;
pub use proxy::{Handle, Interface, WeakInterface};
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
    pub use super::Error as BinderError;
    pub use super::Handle as BinderHandle;
    pub use super::Interface as BinderInterface;
    pub use super::Result as BinderResult;
    pub use super::Service as BinderService;
    pub use super::{Binder, IBinder};
}
