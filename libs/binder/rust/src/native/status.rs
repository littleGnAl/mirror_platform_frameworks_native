use super::libbinder_bindings::{android_binder_Status, android_binder_Status_readFromParcel};
use super::Parcel;
use crate::error::{binder_status, BinderResult};
use std::mem::MaybeUninit;

/// Wrapper for `android::binder::Status`.
#[repr(transparent)]
pub struct Status(android_binder_Status);

impl Status {
    pub fn from_parcel(parcel: &Parcel) -> BinderResult<Self> {
        unsafe {
            let mut status = MaybeUninit::uninit();
            let err = android_binder_Status_readFromParcel(status.as_mut_ptr(), &parcel.0);
            binder_status(err)?;
            Ok(Status(status.assume_init()))
        }
    }
}

impl From<Status> for BinderResult<()> {
    fn from(status: Status) -> Self {
        // TODO: return both Exceptions and low level transaction codes
        binder_status(status.0.mErrorCode)
    }
}
