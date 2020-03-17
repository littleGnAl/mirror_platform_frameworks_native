//! Rust API for implementing a binder service.

use crate::error::BinderResult;
use crate::native;

pub use native::BinderNative;

/// A struct that is remotable via Binder.
///
/// This is a low-level interface that should normally be automatically
/// generated from AIDL.
pub trait Binder {
    fn on_transact(
        &mut self,
        code: native::TransactionCode,
        data: &native::Parcel,
        reply: &mut native::Parcel,
        flags: native::TransactionFlags,
    ) -> BinderResult<()>;
}

pub use native::BinderNative as BinderService;
