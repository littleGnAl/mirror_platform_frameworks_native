use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result;

pub use crate::sys::status_t;

/// Error codes from Android `libutils`.
// All error codes are negative integer values. Derived from the anonymous enum
// in utils/Errors.h
pub use crate::sys::libbinder_bindings::android_c_interface_Error as Error;

/// A specialized [`Result`](result::Result) for binder operations.
pub type Result<T> = result::Result<T, Error>;

/// Convert a native [`status_t`] error code to the idiomatic Rust result type
pub fn binder_status(status: status_t) -> Result<()> {
    if status == Error::OK as i32 {
        Ok(())
    } else if status == Error::NO_MEMORY as i32 {
        Err(Error::NO_MEMORY)
    } else if status == Error::INVALID_OPERATION as i32 {
        Err(Error::INVALID_OPERATION)
    } else if status == Error::BAD_VALUE as i32 {
        Err(Error::BAD_VALUE)
    } else if status == Error::BAD_TYPE as i32 {
        Err(Error::BAD_TYPE)
    } else if status == Error::NAME_NOT_FOUND as i32 {
        Err(Error::NAME_NOT_FOUND)
    } else if status == Error::PERMISSION_DENIED as i32 {
        Err(Error::PERMISSION_DENIED)
    } else if status == Error::NO_INIT as i32 {
        Err(Error::NO_INIT)
    } else if status == Error::ALREADY_EXISTS as i32 {
        Err(Error::ALREADY_EXISTS)
    } else if status == Error::DEAD_OBJECT as i32 {
        Err(Error::DEAD_OBJECT)
    } else if status == Error::FAILED_TRANSACTION as i32 {
        Err(Error::FAILED_TRANSACTION)
    } else if status == Error::BAD_INDEX as i32 {
        Err(Error::BAD_INDEX)
    } else if status == Error::NOT_ENOUGH_DATA as i32 {
        Err(Error::NOT_ENOUGH_DATA)
    } else if status == Error::WOULD_BLOCK as i32 {
        Err(Error::WOULD_BLOCK)
    } else if status == Error::TIMED_OUT as i32 {
        Err(Error::TIMED_OUT)
    } else if status == Error::UNKNOWN_TRANSACTION as i32 {
        Err(Error::UNKNOWN_TRANSACTION)
    } else if status == Error::FDS_NOT_ALLOWED as i32 {
        Err(Error::FDS_NOT_ALLOWED)
    } else if status == Error::UNEXPECTED_NULL as i32 {
        Err(Error::UNEXPECTED_NULL)
    } else {
        Err(Error::UNKNOWN_ERROR)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Error::{:?}", self)
    }
}

impl error::Error for Error {}
