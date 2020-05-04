//! Unsafe native interfaces to the C++ libbinder library. No user servicable
//! parts here.

mod status;

#[cfg(test)]
mod tests;

pub use binder_rs_sys::*;
pub use status::Status;
