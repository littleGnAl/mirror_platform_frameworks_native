use crate::error::{binder_status, Result};
use crate::parcel::Parcel;
use crate::sys::libbinder_bindings::*;
use crate::utils::AsNative;

impl android_binder_Status {
    fn new() -> Self {
        android_binder_Status {
            mException: 0,
            mErrorCode: 0,
            mMessage: unsafe { android_String8::new() },
        }
    }
}

/// Wrapper for `android_binder::Status`.
// TODO: Do we want to rely on this being a POD type or should we treat it as an
// opaque pointer too?
#[repr(transparent)]
pub struct Status(android_binder_Status);

impl Status {
    pub fn from_parcel(parcel: &Parcel) -> Result<Self> {
        unsafe {
            let mut status = android_binder_Status::new();
            let err =
                android_binder_Status_readFromParcel(&mut status as *mut _, parcel.as_native());
            binder_status(err)?;
            Ok(Status(status))
        }
    }
}

impl From<Status> for Result<()> {
    fn from(status: Status) -> Self {
        // TODO: return both Exceptions and low level transaction codes
        binder_status(status.0.mErrorCode)
    }
}
