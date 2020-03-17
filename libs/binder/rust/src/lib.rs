//! Rust interface to Android `libbinder`

#[macro_use]
mod utils;
#[macro_use]
mod proxy;

mod error;
mod native;
mod service_manager; // Needs to be merged with crate::interfaces::service_manager?
mod state;
mod sys;

pub mod interfaces;
pub mod parcel;

pub use error::binder_status;
pub use error::{status_t, Error, Result};
pub use native::{Binder, Service};
pub use proxy::get_service;
pub use proxy::{Handle, Interface, TransactionCode, TransactionFlags};
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
}
