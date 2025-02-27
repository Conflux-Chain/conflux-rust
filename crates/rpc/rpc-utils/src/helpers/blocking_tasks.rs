//! Spawns a blocking task. CPU heavy tasks are executed with the `rayon`
//! library. IO heavy tasks are executed on the `tokio` runtime.

use crate::error::EthApiError;
use cfx_tasks::TaskSpawner;
use futures::Future;
use jsonrpsee::types::ErrorObjectOwned;
use tokio::sync::oneshot;

/// Executes code on a blocking thread.
pub trait SpawnBlocking: Clone + Send + Sync + 'static {
    /// Returns a handle for spawning IO heavy blocking tasks.
    ///
    /// Runtime access in default trait method implementations.
    fn io_task_spawner(&self) -> impl TaskSpawner;

    /// Executes the future on a new blocking task.
    ///
    /// Note: This is expected for futures that are dominated by blocking IO
    /// operations, for tracing or CPU bound operations in general use
    /// [`spawn_tracing`](Self::spawn_tracing).
    fn spawn_blocking_io<F, R>(
        &self, f: F,
    ) -> impl Future<Output = Result<R, ErrorObjectOwned>> + Send
    where
        F: FnOnce(Self) -> Result<R, ErrorObjectOwned> + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let this = self.clone();
        self.io_task_spawner().spawn_blocking(Box::pin(async move {
            let res = f(this);
            let _ = tx.send(res);
        }));

        async move {
            rx.await.map_err(|_| {
                ErrorObjectOwned::from(EthApiError::InternalEthError)
            })?
        }
    }
}
