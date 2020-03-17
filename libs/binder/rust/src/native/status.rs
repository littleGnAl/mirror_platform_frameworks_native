use super::libbinder_bindings::*;
use super::Parcel;
use super::utils::AsNative;
use crate::error::{binder_status, BinderResult};

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
#[repr(transparent)]
pub struct Status(android_binder_Status);

impl Status {
    pub fn from_parcel(parcel: &Parcel) -> BinderResult<Self> {
        unsafe {
            let mut status = android_binder_Status::new();
            let err = android_binder_Status_readFromParcel(&mut status as *mut _, parcel.as_native());
            binder_status(err)?;
            Ok(Status(status))
        }
    }
}

impl From<Status> for BinderResult<()> {
    fn from(status: Status) -> Self {
        // TODO: return both Exceptions and low level transaction codes
        binder_status(status.0.mErrorCode)
    }
}
