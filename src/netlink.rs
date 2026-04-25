use std::future::Future;

use anyhow::{Context, Result};
use tokio::task::block_in_place;

/// Connect to netlink, spawn the connection task, and run an async closure with the handle.
///
/// The closure must return `anyhow::Result<R>`.
/// Typical usage:
///   netlink::with_handle(|handle| async move {
///       handle.route().add()...execute().await?;
///       Ok(())
///   }).await
pub async fn with_handle<F, Fut, R>(f: F) -> Result<R>
where
    F: FnOnce(rtnetlink::Handle) -> Fut,
    Fut: Future<Output = anyhow::Result<R>> + Send + 'static,
    R: Send + 'static,
{
    let (connection, handle, _) =
        rtnetlink::new_connection().context("create netlink connection")?;
    let conn = tokio::spawn(connection);
    let result = block_in_place(|| {
        tokio::runtime::Handle::current().block_on(f(handle))
    });
    conn.abort();
    result
}

/// Check if a network interface exists by name.
pub async fn interface_exists(name: &str) -> bool {
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let conn = tokio::spawn(connection);
    let exists = block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            use futures::TryStreamExt;
            let mut links = handle.link().get().match_name(name.to_string()).execute();
            links.try_next().await.ok().flatten().is_some()
        })
    });
    conn.abort();
    exists
}
