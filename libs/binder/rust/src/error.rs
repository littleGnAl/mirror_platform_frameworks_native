use crate::native;
use libc;

/// Error codes from Android libutils.
///
/// All error codes are negative values.
// Derived from the anonymous enum in utils/Errors.h
#[repr(i32)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinderError {
    OK = 0, // Preferred constant for checking success.

    UNKNOWN_ERROR = (-2147483647 - 1), // INT32_MIN value

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

    FDS_NOT_ALLOWED = (Self::UNKNOWN_ERROR as i32 + 7),
    UNEXPECTED_NULL = (Self::UNKNOWN_ERROR as i32 + 8),
}

pub type BinderResult<T> = Result<T, BinderError>;

/// Convert a native [`native::status_t`] error code to the idiomatic Rust result type
pub fn binder_status(status: native::status_t) -> BinderResult<()> {
    if status == BinderError::OK as i32 {
        Ok(())
    } else if status == BinderError::NO_MEMORY as i32 {
        Err(BinderError::NO_MEMORY)
    } else if status == BinderError::INVALID_OPERATION as i32 {
        Err(BinderError::INVALID_OPERATION)
    } else if status == BinderError::BAD_VALUE as i32 {
        Err(BinderError::BAD_VALUE)
    } else if status == BinderError::BAD_TYPE as i32 {
        Err(BinderError::BAD_TYPE)
    } else if status == BinderError::NAME_NOT_FOUND as i32 {
        Err(BinderError::NAME_NOT_FOUND)
    } else if status == BinderError::PERMISSION_DENIED as i32 {
        Err(BinderError::PERMISSION_DENIED)
    } else if status == BinderError::NO_INIT as i32 {
        Err(BinderError::NO_INIT)
    } else if status == BinderError::ALREADY_EXISTS as i32 {
        Err(BinderError::ALREADY_EXISTS)
    } else if status == BinderError::DEAD_OBJECT as i32 {
        Err(BinderError::DEAD_OBJECT)
    } else if status == BinderError::FAILED_TRANSACTION as i32 {
        Err(BinderError::FAILED_TRANSACTION)
    } else if status == BinderError::BAD_INDEX as i32 {
        Err(BinderError::BAD_INDEX)
    } else if status == BinderError::NOT_ENOUGH_DATA as i32 {
        Err(BinderError::NOT_ENOUGH_DATA)
    } else if status == BinderError::WOULD_BLOCK as i32 {
        Err(BinderError::WOULD_BLOCK)
    } else if status == BinderError::TIMED_OUT as i32 {
        Err(BinderError::TIMED_OUT)
    } else if status == BinderError::UNKNOWN_TRANSACTION as i32 {
        Err(BinderError::UNKNOWN_TRANSACTION)
    } else if status == BinderError::FDS_NOT_ALLOWED as i32 {
        Err(BinderError::FDS_NOT_ALLOWED)
    } else if status == BinderError::UNEXPECTED_NULL as i32 {
        Err(BinderError::UNEXPECTED_NULL)
    } else {
        Err(BinderError::UNKNOWN_ERROR)
    }
}
