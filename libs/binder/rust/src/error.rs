pub use crate::sys::status_t;
use libc;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result;

/// Error codes from Android `libutils`.
// All error codes are negative integer values. Derived from the anonymous enum
// in utils/Errors.h
#[repr(i32)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    OK = 0, // Preferred constant for checking success.

    UNKNOWN_ERROR = i32::min_value(),

    NO_MEMORY = -libc::ENOMEM,
    INVALID_OPERATION = -libc::ENOSYS,
    BAD_VALUE = -libc::EINVAL,
    BAD_TYPE = (Self::UNKNOWN_ERROR as i32 + 1),
    NAME_NOT_FOUND = -libc::ENOENT,
    PERMISSION_DENIED = -libc::EPERM,
    NO_INIT = -libc::ENODEV,
    ALREADY_EXISTS = -libc::EEXIST,
    DEAD_OBJECT = -libc::EPIPE,
    FAILED_TRANSACTION = (Self::UNKNOWN_ERROR as i32 + 2),

    #[cfg(not(windows))]
    BAD_INDEX = -libc::EOVERFLOW,
    #[cfg(not(windows))]
    NOT_ENOUGH_DATA = -libc::ENODATA,
    #[cfg(not(windows))]
    WOULD_BLOCK = -libc::EWOULDBLOCK,
    #[cfg(not(windows))]
    TIMED_OUT = -libc::ETIMEDOUT,
    #[cfg(not(windows))]
    UNKNOWN_TRANSACTION = -libc::EBADMSG,
    #[cfg(not(windows))]
    BUSY = -libc::EBUSY,

    #[cfg(windows)]
    BAD_INDEX = -libc::E2BIG,
    #[cfg(windows)]
    NOT_ENOUGH_DATA = (Self::UNKNOWN_ERROR as i32 + 3),
    #[cfg(windows)]
    WOULD_BLOCK = (Self::UNKNOWN_ERROR as i32 + 4),
    #[cfg(windows)]
    TIMED_OUT = (Self::UNKNOWN_ERROR as i32 + 5),
    #[cfg(windows)]
    UNKNOWN_TRANSACTION = (Self::UNKNOWN_ERROR as i32 + 6),
    // TODO: Windows BUSY?

    FDS_NOT_ALLOWED = (Self::UNKNOWN_ERROR as i32 + 7),
    UNEXPECTED_NULL = (Self::UNKNOWN_ERROR as i32 + 8),
}

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
