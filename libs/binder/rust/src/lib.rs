//! Rust interface to Android libbinder

mod error;
mod native;

#[macro_use]
pub mod client;
pub use client::get_service;

pub use native::start_thread_pool;
pub use native::{Parcel, Parcelable, TransactionCode, TransactionFlags, String8, String16};
pub use error::{BinderError, BinderResult, binder_status};

pub mod service;

pub mod interfaces;
