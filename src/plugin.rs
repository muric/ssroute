use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

/// A running SIP003-compatible plugin process.
pub struct PluginProcess {
    child: tokio::process::Child,
    pub local_addr: String,
}

/// Start a SIP003-compatible plugin (e.g. v2ray-plugin).
///
/// The plugin creates a tunnel between a local port and the remote SS server,
/// applying obfuscation to the traffic.
///
/// SIP003 protocol:
/// - Plugin receives config via environment variables
/// - Plugin listens on SS_LOCAL_HOST:SS_LOCAL_PORT
/// - Plugin forwards traffic to SS_REMOTE_HOST:SS_REMOTE_PORT
/// - The SS proxy connects to the local port instead of the server directly
pub async fn start_plugin(
    plugin: &str,
    plugin_opts: &str,
    remote_host: &str,
    remote_port: u16,
) -> Result<PluginProcess> {
    let local_port = find_free_port().await?;
    let local_host = "127.0.0.1";
    let local_addr = format!("{local_host}:{local_port}");

    let mut cmd = Command::new(plugin);
    cmd.env("SS_REMOTE_HOST", remote_host)
        .env("SS_REMOTE_PORT", remote_port.to_string())
        .env("SS_LOCAL_HOST", local_host)
        .env("SS_LOCAL_PORT", local_port.to_string())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    if !plugin_opts.is_empty() {
        cmd.env("SS_PLUGIN_OPTIONS", plugin_opts);
    }

    let child = cmd.spawn().with_context(|| format!("start plugin {plugin}"))?;
    let pid = child.id().unwrap_or(0);

    // Poll-connect until the plugin is ready (up to 5 seconds)
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(&local_addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    if ready.is_err() {
        tracing::warn!("Plugin {plugin} did not become ready within 5s, continuing anyway");
    }

    tracing::info!("Plugin {plugin} started (pid={pid}), listening on {local_addr}");

    Ok(PluginProcess { child, local_addr })
}

/// Ensure the plugin binary is available and executable.
pub async fn ensure_plugin_available(plugin: &str) -> Result<()> {
    let status = Command::new(plugin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .with_context(|| format!("failed to exec plugin: {}", plugin))?;

    if !status.success() {
        bail!("plugin '{}' is not available (exit status={})", plugin, status);
    }
    Ok(())
}

/// Start SIP003 plugin wrapper (checks binary first).
pub async fn start_sip003_plugin(
    plugin: &str,
    plugin_opts: &str,
    remote_host: &str,
    remote_port: u16,
) -> Result<PluginProcess> {
    ensure_plugin_available(plugin).await?;
    start_plugin(plugin, plugin_opts, remote_host, remote_port).await
}

/// Start XRay plugin specifically (alias for SIP003 wrapper).
pub async fn start_xray_plugin(
    plugin: &str,
    plugin_opts: &str,
    remote_host: &str,
    remote_port: u16,
) -> Result<PluginProcess> {
    start_sip003_plugin(plugin, plugin_opts, remote_host, remote_port).await
}

/// Gracefully stop a running plugin process.
/// Sends SIGTERM first, waits up to 5 seconds, then SIGKILL.
pub async fn stop_plugin(process: &mut PluginProcess) {
    let Some(pid) = process.child.id() else {
        return;
    };

    tracing::info!("Stopping plugin (pid={pid})...");

    // Send SIGTERM
    let pid_i32 = pid as i32;
    if let Err(e) = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid_i32),
        nix::sys::signal::Signal::SIGTERM,
    ) {
        tracing::warn!("Failed to send SIGTERM to plugin: {e}");
        let _ = process.child.kill().await;
        return;
    }

    // Wait with timeout
    let result = tokio::time::timeout(Duration::from_secs(5), process.child.wait()).await;

    match result {
        Ok(Ok(_)) => {
            tracing::info!("Plugin stopped gracefully");
        }
        Ok(Err(e)) => {
            tracing::warn!("Error waiting for plugin: {e}");
        }
        Err(_) => {
            tracing::info!("Plugin did not stop in time, sending SIGKILL");
            let _ = process.child.kill().await;
            let _ = process.child.wait().await;
        }
    }
}

async fn find_free_port() -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}
