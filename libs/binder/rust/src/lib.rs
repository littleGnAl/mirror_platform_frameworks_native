//! Rust interface to Android libbinder

mod error;
mod native;

#[macro_use]
pub mod client;
pub use client::get_service;

pub use native::start_thread_pool;
pub use native::{Parcel, TransactionCode, TransactionFlags};

pub use error::{BinderError, BinderResult};

pub mod service;

pub mod interfaces;
