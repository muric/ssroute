mod config;
mod icmp;
mod plugin;
mod proxy;
mod route;
mod stats;
mod tun;
mod tunnel;

use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Result};
use config::ObfsMode;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Step 1: Read config first — everything else depends on it
    let config = config::read_config(Path::new("ssroute.conf"))?;

    // Step 2: Dispatch based on ss_enabled
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

    // Add routes for TUN interface from data/
    if !config.interface.is_empty() && !config.gateway.is_empty() {
        tracing::info!("Adding routes for interface: {}", config.interface);
        if let Err(e) = route::add_routes_from_dir(
            route::main_route_dir(),
            &config.gateway,
            &config.interface,
            config.concurrency,
            config.debug,
            &stats,
        )
        .await
        {
            tracing::error!("Error adding routes: {e}");
        }
    }

    // Add routes for default interface from default_route/
    if !config.default_interface.is_empty() && !config.default_gateway.is_empty() {
        tracing::info!(
            "Adding routes for default interface: {}",
            config.default_interface
        );
        if let Err(e) = route::add_routes_from_dir(
            route::default_route_dir(),
            &config.default_gateway,
            &config.default_interface,
            config.concurrency,
            config.debug,
            &stats,
        )
        .await
        {
            tracing::error!("Error adding default routes: {e}");
        }
    }

    // We need a mutable reference for close()
    // Since Arc doesn't allow mut, we use try_unwrap
    let stats_ref = &*stats;
    stats_ref.print_stats();
    // Note: duplicates writer will be dropped when Arc is dropped
    // For a clean shutdown, we'd need to restructure this.
    // In oneshot mode, the process exits immediately anyway.

    Ok(())
}

/// Daemon mode: create non-persistent TUN, start SS client, add routes, run forever.
async fn run_daemon_mode(config: &config::Config) -> Result<()> {
    // Validate SS configuration
    if config.ss_server.is_empty() || config.ss_server_port == 0 || config.ss_password.is_empty() {
        bail!(
            "Shadowsocks is enabled but ss_server, ss_server_port, or ss_password is not set"
        );
    }

    tracing::info!("Creating non-persistent TUN interface (will be destroyed on exit)");
    let tun_fd = tun::create_tun(&config.interface, false)?
        .expect("non-persistent TUN should return an fd");

    tracing::info!(
        "Setting gateway IP and MTU={} on TUN interface",
        config.mtu
    );
    tun::configure_tun(&config.interface, &config.gateway, config.mtu).await?;

    // Set TUN fd to non-blocking for poll-based I/O
    tun::set_nonblock(tun_fd.as_raw_fd())?;

    // Determine SS server address (may be overridden by plugin)
    let mut ss_addr = format!("{}:{}", config.ss_server, config.ss_server_port);
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
            ss_addr = p.local_addr.clone();
            plugin_process = Some(p);
        }
        ObfsMode::SimpleObfs => {
            tracing::info!("Using simple-obfs with host: {}", config.obfs_host);
            // simple-obfs is not implemented (was TODO in Go code too)
        }
        ObfsMode::Disable => {}
    }

    // Create SS proxy
    let proxy = proxy::SsProxy::new(&ss_addr, &config.ss_method, &config.ss_password)?;

    // Create tunnel
    let tunnel = tunnel::Tunnel::new(tun_fd, config.mtu, proxy)?;

    // Add routes
    let stats = Arc::new(stats::Stats::new());

    if !config.interface.is_empty() && !config.gateway.is_empty() {
        tracing::info!("Adding routes for interface: {}", config.interface);
        if let Err(e) = route::add_routes_from_dir(
            route::main_route_dir(),
            &config.gateway,
            &config.interface,
            config.concurrency,
            config.debug,
            &stats,
        )
        .await
        {
            tracing::error!("Error adding routes: {e}");
        }
    }

    if !config.default_interface.is_empty() && !config.default_gateway.is_empty() {
        tracing::info!(
            "Adding routes for default interface: {}",
            config.default_interface
        );
        if let Err(e) = route::add_routes_from_dir(
            route::default_route_dir(),
            &config.default_gateway,
            &config.default_interface,
            config.concurrency,
            config.debug,
            &stats,
        )
        .await
        {
            tracing::error!("Error adding default routes: {e}");
        }
    }

    stats.print_stats();

    tracing::info!("Daemon running!!!");

    // Block on signals
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT, shutting down...");
        }
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, shutting down...");
        }
    }

    // Shutdown sequence
    tunnel.close().await;

    if let Some(mut p) = plugin_process {
        plugin::stop_plugin(&mut p).await;
    }

    Ok(())
}
