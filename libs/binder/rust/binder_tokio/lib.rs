/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! This crate lets you use the Tokio `spawn_blocking` pool with AIDL in async
//! Rust code.
//!
//! This crate works by defining a type [`Tokio`], which you can use as the
//! generic parameter in the async version of the trait generated by the AIDL
//! compiler.
//! ```text
//! use binder_tokio::Tokio;
//!
//! binder::get_interface::<dyn SomeAsyncInterface<Tokio>>("...").
//! ```
//!
//! [`Tokio`]: crate::Tokio

use binder::{BinderAsyncPool, BoxFuture, FromIBinder, StatusCode, Strong};
use binder::binder_impl::BinderAsyncRuntime;
use std::future::Future;

/// Retrieve an existing service for a particular interface, sleeping for a few
/// seconds if it doesn't yet exist.
pub async fn get_interface<T: FromIBinder + ?Sized + 'static>(name: &str) -> Result<Strong<T>, StatusCode> {
    if binder::is_handling_transaction() {
        // See comment in the BinderAsyncPool impl.
        return binder::get_interface::<T>(name);
    }

    let name = name.to_string();
    let res = tokio::task::spawn_blocking(move || {
        binder::get_interface::<T>(&name)
    }).await;

    // The `is_panic` branch is not actually reachable in Android as we compile
    // with `panic = abort`.
    match res {
        Ok(Ok(service)) => Ok(service),
        Ok(Err(err)) => Err(err),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) if e.is_cancelled() => Err(StatusCode::FAILED_TRANSACTION),
        Err(_) => Err(StatusCode::UNKNOWN_ERROR),
    }
}

/// Retrieve an existing service for a particular interface, or start it if it
/// is configured as a dynamic service and isn't yet started.
pub async fn wait_for_interface<T: FromIBinder + ?Sized + 'static>(name: &str) -> Result<Strong<T>, StatusCode> {
    if binder::is_handling_transaction() {
        // See comment in the BinderAsyncPool impl.
        return binder::wait_for_interface::<T>(name);
    }

    let name = name.to_string();
    let res = tokio::task::spawn_blocking(move || {
        binder::wait_for_interface::<T>(&name)
    }).await;

    // The `is_panic` branch is not actually reachable in Android as we compile
    // with `panic = abort`.
    match res {
        Ok(Ok(service)) => Ok(service),
        Ok(Err(err)) => Err(err),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) if e.is_cancelled() => Err(StatusCode::FAILED_TRANSACTION),
        Err(_) => Err(StatusCode::UNKNOWN_ERROR),
    }
}

/// Use the Tokio `spawn_blocking` pool with AIDL.
pub enum Tokio {}

impl BinderAsyncPool for Tokio {
    fn spawn<'a, F1, F2, Fut, A, B, E>(spawn_me: F1, after_spawn: F2) -> BoxFuture<'a, Result<B, E>>
    where
        F1: FnOnce() -> A,
        F2: FnOnce(A) -> Fut,
        Fut: Future<Output = Result<B, E>>,
        F1: Send + 'static,
        F2: Send + 'a,
        Fut: Send + 'a,
        A: Send + 'static,
        B: Send + 'a,
        E: From<crate::StatusCode>,
    {
        if binder::is_handling_transaction() {
            // We are currently on the thread pool for a binder server, so we should execute the
            // transaction on the current thread so that the binder kernel driver is able to apply
            // its deadlock prevention strategy to the sub-call.
            //
            // This shouldn't cause issues with blocking the thread as only one task will run in a
            // call to `block_on`, so there aren't other tasks to block.
            let result = spawn_me();
            Box::pin(after_spawn(result))
        } else {
            let handle = tokio::task::spawn_blocking(spawn_me);
            Box::pin(async move {
                // The `is_panic` branch is not actually reachable in Android as we compile
                // with `panic = abort`.
                match handle.await {
                    Ok(res) => after_spawn(res).await,
                    Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                    Err(e) if e.is_cancelled() => Err(StatusCode::FAILED_TRANSACTION.into()),
                    Err(_) => Err(StatusCode::UNKNOWN_ERROR.into()),
                }
            })
        }
    }
}

/// Wrapper around Tokio runtime types for providing a runtime to a binder server.
pub struct TokioRuntime<R>(pub R);

impl BinderAsyncRuntime for TokioRuntime<tokio::runtime::Runtime> {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }
}

impl BinderAsyncRuntime for TokioRuntime<std::sync::Arc<tokio::runtime::Runtime>> {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }
}

impl BinderAsyncRuntime for TokioRuntime<tokio::runtime::Handle> {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }
}
