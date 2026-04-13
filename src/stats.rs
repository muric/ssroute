use std::sync::atomic::{AtomicI64, Ordering};


pub struct Stats {
    pub success: AtomicI64,
    pub already_exist: AtomicI64,
    pub network_unreachable: AtomicI64,
    pub operation_not_permitted: AtomicI64,
    pub invalid_argument: AtomicI64,
    pub no_route_to_host: AtomicI64,
    pub unknown_error: AtomicI64,
}

impl Stats {
    pub fn new() -> Self {
        // Disabled: duplicate route logging was causing memory leak
        Self::new_with_filename("disabled".to_string())
    }

    pub(crate) fn new_with_filename(_filename: String) -> Self {
        Self {
            success: AtomicI64::new(0),
            already_exist: AtomicI64::new(0),
            network_unreachable: AtomicI64::new(0),
            operation_not_permitted: AtomicI64::new(0),
            invalid_argument: AtomicI64::new(0),
            no_route_to_host: AtomicI64::new(0),
            unknown_error: AtomicI64::new(0),
        }
    }

    pub fn add_success(&self) {
        self.success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_already_exist(&self, _route: String) {
        self.already_exist.fetch_add(1, Ordering::Relaxed);
        // Disabled: duplicate route logging was causing memory leak
        // Keep only the counter for monitoring purposes
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

    pub async fn shutdown(&mut self) {
        // No-op: duplicate route logging is disabled
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

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_stats_counters() {
        let mut stats = Stats::new_with_filename("test".to_string());

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
