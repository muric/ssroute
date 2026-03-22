use std::sync::atomic::{AtomicI64, Ordering};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const DUPLICATES_FLUSH_THRESHOLD: usize = 10_000;
const DUPLICATES_CHAN_BUFFER: usize = 50_000;
const DUPLICATES_FILE_PREFIX: &str = "/tmp/route_duplicates_";
/// Flush the buffer at least once every this many seconds, even if the
/// threshold has not been reached yet. This prevents duplicate-route strings
/// from accumulating in the in-process buffer indefinitely.
const DUPLICATES_FLUSH_INTERVAL_SECS: u64 = 60;

pub struct Stats {
    pub success: AtomicI64,
    pub already_exist: AtomicI64,
    pub network_unreachable: AtomicI64,
    pub operation_not_permitted: AtomicI64,
    pub invalid_argument: AtomicI64,
    pub no_route_to_host: AtomicI64,
    pub unknown_error: AtomicI64,

    dup_sender: Option<mpsc::Sender<String>>,
    writer_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Stats {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(DUPLICATES_CHAN_BUFFER);
        let filename = format!(
            "{}{}.log",
            DUPLICATES_FILE_PREFIX,
            chrono_like_now()
        );
        let handle = tokio::spawn(duplicates_writer(rx, filename));

        Self {
            success: AtomicI64::new(0),
            already_exist: AtomicI64::new(0),
            network_unreachable: AtomicI64::new(0),
            operation_not_permitted: AtomicI64::new(0),
            invalid_argument: AtomicI64::new(0),
            no_route_to_host: AtomicI64::new(0),
            unknown_error: AtomicI64::new(0),
            dup_sender: Some(tx),
            writer_handle: Some(handle),
        }
    }

    pub fn add_success(&self) {
        self.success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_already_exist(&self, route: String) {
        self.already_exist.fetch_add(1, Ordering::Relaxed);
        if let Some(ref tx) = self.dup_sender {
            let _ = tx.try_send(route);
        }
    }

    pub fn add_error(&self, err_type: &str) {
        match err_type {
            "network_unreachable" => self.network_unreachable.fetch_add(1, Ordering::Relaxed),
            "operation_not_permitted" => self.operation_not_permitted.fetch_add(1, Ordering::Relaxed),
            "invalid_argument" => self.invalid_argument.fetch_add(1, Ordering::Relaxed),
            "no_route_to_host" => self.no_route_to_host.fetch_add(1, Ordering::Relaxed),
            _ => self.unknown_error.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Close the duplicates channel and wait for the writer to flush.
    pub async fn shutdown(&mut self) {
        // Drop sender to signal writer to finish
        self.dup_sender.take();
        if let Some(handle) = self.writer_handle.take() {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                handle,
            )
            .await;
        }
    }

    pub fn print_stats(&self) {
        let success = self.success.load(Ordering::Relaxed);
        let already_exist = self.already_exist.load(Ordering::Relaxed);
        let network_unreachable = self.network_unreachable.load(Ordering::Relaxed);
        let operation_not_permitted = self.operation_not_permitted.load(Ordering::Relaxed);
        let invalid_argument = self.invalid_argument.load(Ordering::Relaxed);
        let no_route_to_host = self.no_route_to_host.load(Ordering::Relaxed);
        let unknown_error = self.unknown_error.load(Ordering::Relaxed);

        let mut msg = String::new();
        msg.push_str("\n========== Statistics ==========\n");
        msg.push_str(&format!("Successfully added: {success}\n"));
        msg.push_str(&format!("Already existed (skipped): {already_exist}\n"));

        if network_unreachable > 0 {
            msg.push_str(&format!("Network unreachable: {network_unreachable}\n"));
        }
        if operation_not_permitted > 0 {
            msg.push_str(&format!("Operation not permitted: {operation_not_permitted}\n"));
        }
        if invalid_argument > 0 {
            msg.push_str(&format!("Invalid argument: {invalid_argument}\n"));
        }
        if no_route_to_host > 0 {
            msg.push_str(&format!("No route to host: {no_route_to_host}\n"));
        }
        if unknown_error > 0 {
            msg.push_str(&format!("Unknown errors: {unknown_error}\n"));
        }

        let total_errors =
            already_exist + network_unreachable + operation_not_permitted + invalid_argument + no_route_to_host + unknown_error;
        msg.push_str(&format!("Total processed: {}\n", success + total_errors));
        msg.push_str("================================");

        tracing::info!("{msg}");
    }

}

/// Classify error from error message string.
pub fn classify_error_str(err: &str) -> &'static str {
    let err_lower = err.to_lowercase();
    if err_lower.contains("file exists") {
        "file_exists"
    } else if err_lower.contains("network is unreachable") {
        "network_unreachable"
    } else if err_lower.contains("no such device") {
        "no_such_device"
    } else if err_lower.contains("operation not permitted") {
        "operation_not_permitted"
    } else if err_lower.contains("invalid argument") {
        "invalid_argument"
    } else if err_lower.contains("no route to host") {
        "no_route_to_host"
    } else {
        "unknown"
    }
}

async fn duplicates_writer(mut rx: mpsc::Receiver<String>, filename: String) {
    let mut buffer: Vec<String> = Vec::with_capacity(DUPLICATES_FLUSH_THRESHOLD);
    let mut file: Option<tokio::fs::File> = None;
    let flush_interval = std::time::Duration::from_secs(DUPLICATES_FLUSH_INTERVAL_SECS);

    loop {
        // Wait for a message or a flush-interval timeout
        match tokio::time::timeout(flush_interval, rx.recv()).await {
            Ok(Some(route)) => {
                buffer.push(route);
                if buffer.len() >= DUPLICATES_FLUSH_THRESHOLD {
                    flush_buffer(&mut buffer, &mut file, &filename).await;
                }
            }
            Ok(None) => {
                // Channel closed (sender dropped) – flush remaining and exit.
                break;
            }
            Err(_elapsed) => {
                // Periodic flush so buffered strings don't accumulate in memory.
                flush_buffer(&mut buffer, &mut file, &filename).await;
            }
        }
    }

    // Final flush on shutdown
    flush_buffer(&mut buffer, &mut file, &filename).await;

    if let Some(mut f) = file {
        let _ = f.flush().await;
        tracing::info!("Duplicates written to: {filename}");
    }
}

async fn flush_buffer(
    buffer: &mut Vec<String>,
    file: &mut Option<tokio::fs::File>,
    filename: &str,
) {
    if buffer.is_empty() {
        return;
    }

    if file.is_none() {
        match tokio::fs::File::create(filename).await {
            Ok(f) => *file = Some(f),
            Err(e) => {
                tracing::error!("Error creating duplicates file: {e}");
                buffer.clear();
                return;
            }
        }
    }

    if let Some(ref mut f) = file {
        let mut data = String::new();
        for dup in buffer.iter() {
            data.push_str(dup);
            data.push('\n');
        }
        if let Err(e) = f.write_all(data.as_bytes()).await {
            tracing::error!("Error writing duplicates: {e}");
        }
    }

    buffer.clear();
    // Release the backing allocation so flushed strings don't keep memory pinned.
    buffer.shrink_to_fit();
}

/// Simple timestamp without chrono dependency.
fn chrono_like_now() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", dur.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stats_counters() {
        let mut stats = Stats::new();
        stats.add_success();
        stats.add_success();
        stats.add_already_exist("10.0.0.1/32 via 10.8.0.1 dev tun0".to_string());
        stats.add_error("network_unreachable");
        stats.add_error("invalid_argument");
        stats.add_error("unknown_kind");

        assert_eq!(stats.success.load(Ordering::Relaxed), 2);
        assert_eq!(stats.already_exist.load(Ordering::Relaxed), 1);
        assert_eq!(stats.network_unreachable.load(Ordering::Relaxed), 1);
        assert_eq!(stats.invalid_argument.load(Ordering::Relaxed), 1);
        assert_eq!(stats.unknown_error.load(Ordering::Relaxed), 1);

        stats.shutdown().await;
    }

    #[tokio::test]
    async fn test_shutdown_flushes_duplicates() {
        // Create Stats, send a few duplicates below the flush threshold,
        // then shut down and verify the writer task terminates cleanly.
        let mut stats = Stats::new();
        for i in 0..5 {
            stats.add_already_exist(format!("192.168.{i}.0/24 via 10.8.0.1 dev tun0"));
        }
        // shutdown() must complete (writer task exits) within its 5-second timeout.
        stats.shutdown().await;
        // After shutdown the handle should be gone.
        assert!(stats.writer_handle.is_none());
        assert!(stats.dup_sender.is_none());
    }

    #[tokio::test]
    async fn test_classify_error_str() {
        assert_eq!(classify_error_str("File exists (os error 17)"), "file_exists");
        assert_eq!(classify_error_str("Network is unreachable"), "network_unreachable");
        assert_eq!(classify_error_str("No such device"), "no_such_device");
        assert_eq!(classify_error_str("Operation not permitted"), "operation_not_permitted");
        assert_eq!(classify_error_str("Invalid argument"), "invalid_argument");
        assert_eq!(classify_error_str("No route to host"), "no_route_to_host");
        assert_eq!(classify_error_str("some totally unknown error"), "unknown");
    }
}
