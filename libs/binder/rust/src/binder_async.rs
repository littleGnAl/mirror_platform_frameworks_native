use crate::public_api::Result;
use std::future::Future;
use std::pin::Pin;

/// A type alias for a pinned, boxed future that lets you write shorter code without littering it
/// with Pin, Send and Sync.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

/// A thread pool for running binder transactions.
pub trait BinderAsyncPool {
    /// This function should conceptually behave like this:
    ///
    /// ```text
    /// let result = spawn_thread(|| spawn_me()).await;
    /// return after_spawn(result).await;
    /// ```
    ///
    /// If the spawning fails for some reason, the method may also skip the `after_spawn` closure
    /// and immediately return an error.
    ///
    /// The only difference between different implementations should be which
    /// `spawn_thread` method is used. For Tokio, it would be `tokio::task::spawn_blocking`.
    ///
    /// This method has the design it has because the only way to define a trait that
    /// allows the return type of the spawn to be chosen by the caller is to return a
    /// boxed `Future` trait object, and including `after_spawn` in the trait function
    /// allows the caller to avoid double-boxing if they want to do anything to the value
    /// returned from the spawned thread.
    fn spawn<'a, F1, F2, Fut, A, B>(spawn_me: F1, after_spawn: F2) -> BoxFuture<'a, Result<B>>
    where
        F1: FnOnce() -> A,
        F2: FnOnce(A) -> Fut,
        Fut: Future<Output = Result<B>>,
        F1: Send + 'static,
        F2: Send + 'a,
        Fut: Send + 'a,
        A: Send + 'static,
        B: Send + 'a;
}
