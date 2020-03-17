//! Rust interfaces corresponding to the binder interfaces that libbinder
//! provides.

mod service_manager;

pub use service_manager::{BpServiceManager, IServiceManager};
