//! This file contains a simple reimplementation of the sync_wrapper crate.
use std::pin::Pin;
use std::future::Future;
use std::task::{Poll, Context};

pub(crate) struct SyncWrapper<T> {
    inner: T,
}

// SAFETY: Implementing Sync for this type makes it safe to send values of type
// &SyncWrapper<T> across threads, but since this type has no &self methods,
// such an immutable reference is useless. In particular, having an
// &SyncWrapper<T> does not let you obtain an &T, so even if T is not Sync, this
// does not let you do anything bad.
//
// Note that this type does not derive `Debug`. Doing that would be unsound
// because it adds an `&self` method to the type.
unsafe impl<T> Sync for SyncWrapper<T> {}

impl<T> SyncWrapper<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
        }
    }
}

impl<T: Future> Future for SyncWrapper<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T::Output> {
        // SAFETY: This performs a pin projection of the `inner` field. This is
        // sound because this type does not expose any APIs that let you move
        // the value in `inner`.
        //
        // This method does not violate the promises made in `unsafe impl Sync`
        // because the method takes `&mut self` and not `&self`.
        unsafe {
            Pin::map_unchecked_mut(self, |me| &mut me.inner).poll(cx)
        }
    }
}
