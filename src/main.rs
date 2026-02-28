mod config;
mod plugin;
mod route;
mod stats;
mod tun;
mod tunnel;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use config::ObfsMode;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Step 1: Read config first
    let config = config::read_config(Path::new("ssroute.conf"))?;

    // Step 2: Dispatch
    if !config.ss_enabled {
        run_oneshot_mode(&config).await?;
    } else {
        run_daemon_mode(&config).await?;
    }

    Ok(())
}

/// Oneshot mode: create persistent TUN, add routes, exit.
async fn run_oneshot_mode(config: &config::Config) -> Result<()> {
    tracing::info!("Creating persistent TUN interface");
    tun::create_tun(&config.interface, true)?;

    tracing::info!("Setting gateway IP and MTU={} on TUN interface", config.mtu);
    tun::configure_tun(&config.interface, &config.gateway, config.mtu).await?;

    let stats = Arc::new(stats::Stats::new());
    add_routes(config, &stats).await;
    stats.print_stats();
    // Ensure duplicates writer flushes before exit
    if let Some(s) = Arc::into_inner(stats) {
        let mut s = s;
        s.shutdown().await;
    }

    Ok(())
}

/// Daemon mode: start SS TUN service, add routes, run forever.
async fn run_daemon_mode(config: &config::Config) -> Result<()> {
    if config.ss_server.is_empty() || config.ss_server_port == 0 || config.ss_password.is_empty() {
        bail!("Shadowsocks is enabled but ss_server, ss_server_port, or ss_password is not set");
    }

    // Handle plugin (v2ray)
    let mut config = config.clone();
    let mut plugin_process = None;

    match config.obfs_mode {
        ObfsMode::V2ray => {
            if config.ss_plugin.is_empty() {
                bail!("obfs_mode=v2ray but ss_plugin is not set");
            }
            let p = plugin::start_plugin(
                &config.ss_plugin,
                &config.ss_plugin_opts,
                &config.ss_server,
                config.ss_server_port,
            )
            .await?;
            // Override SS address to plugin's local address
            let parts: Vec<&str> = p.local_addr.split(':').collect();
            if parts.len() == 2 {
                config.ss_server = parts[0].to_string();
                config.ss_server_port = parts[1].parse().unwrap_or(config.ss_server_port);
            }
            plugin_process = Some(p);
        }
        ObfsMode::SimpleObfs => {
            tracing::info!("Using simple-obfs with host: {}", config.obfs_host);
        }
        ObfsMode::Disable => {}
    }

    // Build shadowsocks-service config
    let ss_config = tunnel::build_ss_config(&config)?;

    // Start SS TUN service in background
    let service_handle = tokio::spawn(async move {
        if let Err(e) = tunnel::run_service(ss_config).await {
            tracing::error!("SS service error: {e}");
        }
    });

    // Wait for TUN interface to appear
    tracing::info!("Waiting for TUN interface '{}' to come up...", config.interface);
    wait_for_interface(&config.interface).await;

    // Set MTU (shadowsocks-service might not set it)
    if config.mtu > 0 {
        if let Err(e) = set_mtu(&config.interface, config.mtu).await {
            tracing::warn!("Failed to set MTU: {e}");
        }
    }

    // Add routes
    let stats = Arc::new(stats::Stats::new());
    add_routes(&config, &stats).await;
    stats.print_stats();

    tracing::info!("Daemon running!!!");

    // Block on signals
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => tracing::info!("Received SIGINT, shutting down..."),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down..."),
        _ = service_handle => tracing::error!("SS service exited unexpectedly"),
    }

    if let Some(mut p) = plugin_process {
        plugin::stop_plugin(&mut p).await;
    }

    Ok(())
}

async fn add_routes(config: &config::Config, stats: &Arc<stats::Stats>) {
    if !config.interface.is_empty() && !config.gateway.is_empty() {
        tracing::info!("Adding routes for interface: {}", config.interface);
        if let Err(e) = route::add_routes_from_dir(
            route::main_route_dir(),
            &config.gateway,
            &config.interface,
            config.concurrency,
            config.debug,
            stats,
        )
        .await
        {
            tracing::error!("Error adding routes: {e}");
        }
    }

    if !config.default_interface.is_empty() && !config.default_gateway.is_empty() {
        tracing::info!("Adding routes for default interface: {}", config.default_interface);
        if let Err(e) = route::add_routes_from_dir(
            route::default_route_dir(),
            &config.default_gateway,
            &config.default_interface,
            config.concurrency,
            config.debug,
            stats,
        )
        .await
        {
            tracing::error!("Error adding default routes: {e}");
        }
    }
}

/// Wait for a network interface to appear (up to 10 seconds).
async fn wait_for_interface(name: &str) {
    for i in 0..20 {
        if interface_exists(name).await {
            tracing::info!("Interface {name} is up");
            return;
        }
        if i == 0 {
            tracing::info!("Waiting for interface {name}...");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tracing::warn!("Interface {name} did not appear within 10 seconds, adding routes anyway");
}

async fn interface_exists(name: &str) -> bool {
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let conn_handle = tokio::spawn(connection);
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    use futures::TryStreamExt;
    let result = links.try_next().await.ok().flatten().is_some();
    conn_handle.abort();
    result
}

async fn set_mtu(name: &str, mtu: u16) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let conn_handle = tokio::spawn(connection);

    use futures::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    if let Some(link) = links.try_next().await? {
        handle
            .link()
            .set(link.header.index)
            .mtu(mtu as u32)
            .execute()
            .await?;
    }

    conn_handle.abort();
    Ok(())
}
