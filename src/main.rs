mod config;
mod netlink;
mod plugin;
mod route;
mod tun;
mod tunnel;

use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use zbus::{Connection, Proxy};

use anyhow::{bail, Context, Result};
use config::ObfsMode;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context as SsContext;
use shadowsocks::crypto::CipherKind;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG_PATHS: &[&str] = &["ssroute.conf", "/etc/ssroute/ssroute.conf"];
const NETWORKD_DIR: &str = "/etc/systemd/network";

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI args (minimal, no clap)
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("ssroute {VERSION}");
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("ssroute {VERSION}");
        println!("Usage: ssroute [--config <path>] [--version]");
        println!();
        println!("Options:");
        println!("  --config <path>  Path to config file (default: ./ssroute.conf or /etc/ssroute/ssroute.conf)");
        println!("  --version, -V    Print version and exit");
        println!("  --help, -h       Print this help and exit");
        println!();
        println!("Environment:");
        println!("  RUST_LOG=debug   Enable verbose debug logging");
        return Ok(());
    }

    let config_path = parse_config_flag(&args)?;

    // Init logging BEFORE parsing config (for config parsing errors)
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // Find config file
    let config_path = find_config(&config_path)?;
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    tracing::info!("Using config: {}", config_path.display());

    // Read config
    let config = config::read_config(&config_path)?;

    // Dispatch
    if !config.ss_enabled {
        run_oneshot_mode(&config, &config_dir).await?;
    } else {
        run_daemon_mode(&config, &config_dir).await?;
    }

    Ok(())
}

/// Parse --config <path> from CLI args.
fn parse_config_flag(args: &[String]) -> Result<Option<PathBuf>> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--config" {
            let path = args
                .get(i + 1)
                .with_context(|| "--config requires a path argument")?;
            return Ok(Some(PathBuf::from(path)));
        }
        if let Some(path) = arg.strip_prefix("--config=") {
            return Ok(Some(PathBuf::from(path)));
        }
    }
    Ok(None)
}

/// Find the config file: explicit path > CWD > /etc/ssroute/
fn find_config(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.canonicalize().unwrap_or_else(|_| path.clone()));
        }
        bail!("config file not found: {}", path.display());
    }

    for candidate in DEFAULT_CONFIG_PATHS {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(p.canonicalize().unwrap_or_else(|_| p.to_path_buf()));
        }
    }

    bail!(
        "config file not found. Searched: {}. Use --config <path> to specify.",
        DEFAULT_CONFIG_PATHS.join(", ")
    );
}

/// Oneshot mode: create persistent TUN, add routes, exit.
async fn run_oneshot_mode(config: &config::Config, config_dir: &Path) -> Result<()> {
    ensure_networkd_config(&config.interface);

    tracing::info!("Creating persistent TUN interface");
    tun::create_tun(&config.interface, true)?;

    tracing::info!("Setting gateway IP and MTU={} on TUN interface", config.mtu);
    tun::configure_tun(
        &config.interface,
        &config.gateway,
        &config.gateway6,
        config.mtu,
    )
    .await?;

    add_routes(config, config_dir).await;

    Ok(())
}

/// Build a shadowsocks ServerConfig from our app config.
/// If obfuscation is enabled, starts the plugin and sets plugin_addr.
fn build_ss_config(
    config: &config::Config,
    plugin_local_addr: Option<std::net::SocketAddr>,
) -> Result<ServerConfig> {
    let cipher: CipherKind = config
        .ss_method
        .parse()
        .map_err(|_| anyhow::anyhow!("unknown cipher: {}", config.ss_method))?;

    let ss_addr = format!("{}:{}", config.ss_server, config.ss_server_port);
    let server_addr: shadowsocks::config::ServerAddr = ss_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid SS server address '{ss_addr}': {e:?}"))?;

    let mut svr_cfg = ServerConfig::new(server_addr, &config.ss_password, cipher)
        .map_err(|e| anyhow::anyhow!("invalid SS config: {e:?}"))?;

    // Configure plugin if needed
    if let Some(plugin_addr) = plugin_local_addr {
        svr_cfg.set_plugin_addr(plugin_addr.into());
    }

    Ok(svr_cfg)
}

/// Start the shadowsocks context.
fn build_ss_context() -> shadowsocks::context::SharedContext {
    let ctx = SsContext::new(ServerType::Local);
    Arc::new(ctx)
}

/// Daemon mode: start TUN-to-SS proxy, add routes, run forever.
async fn run_daemon_mode(config: &config::Config, config_dir: &Path) -> Result<()> {
    if config.ss_server.is_empty() || config.ss_server_port == 0 || config.ss_password.is_empty() {
        bail!("Shadowsocks is enabled but ss_server, ss_server_port, or ss_password is not set");
    }

    let config = config.clone();
    let mut plugin_process: Option<plugin::PluginProcess> = None;
    let mut plugin_local_addr: Option<std::net::SocketAddr> = None;

    match config.obfs_mode {
        ObfsMode::Xray => {
            if config.ss_plugin.is_empty() {
                bail!("obfs_mode=xray but ss_plugin is not set");
            }
            tracing::info!("Starting XRay plugin: {}", config.ss_plugin);
            let p = plugin::start_xray_plugin(
                &config.ss_plugin,
                &config.ss_plugin_opts,
                &config.ss_server,
                config.ss_server_port,
            )
            .await
            .with_context(|| format!("failed to start xray plugin '{}'", config.ss_plugin))?;

            let parts: Vec<&str> = p.local_addr.split(':').collect();
            if parts.len() == 2 {
                let local_host: std::net::IpAddr = parts[0].parse()?;
                let local_port: u16 = parts[1].parse().unwrap_or(config.ss_server_port);
                plugin_local_addr = Some(SocketAddr::new(local_host, local_port));
                plugin_process = Some(p);
            }
        }
        ObfsMode::SimpleObfs => {
            tracing::info!("Using simple-obfs with host: {}", config.obfs_host);
        }
        ObfsMode::Disable => {}
    }

    // Build shadowsocks config and context
    let svr_cfg = build_ss_config(&config, plugin_local_addr)?;
    let ctx = build_ss_context();

    // Create TUN interface (non-persistent — we keep the fd open)
    tracing::info!("Creating TUN interface '{}'", config.interface);
    ensure_networkd_config(&config.interface);
    let tun_fd = tun::create_tun(&config.interface, false)?
        .context("TUN interface creation failed — requires root")?;

    // Wait for the interface to appear
    tracing::info!(
        "Waiting for TUN interface '{}' to come up...",
        config.interface
    );
    wait_for_interface(&config.interface).await;

    if let Err(e) = setup_unmanaged_interface(&config.interface).await {
        tracing::warn!("NetworkManager integration error: {e}");
    }

    // Configure TUN interface: assign IP addresses and MTU
    tracing::info!(
        "Configuring TUN interface {} with gateway={}, gateway6={}, mtu={}",
        config.interface,
        config.gateway,
        config.gateway6,
        config.mtu
    );
    if let Err(e) = tun::configure_tun(
        &config.interface,
        &config.gateway,
        &config.gateway6,
        config.mtu,
    )
    .await
    {
        tracing::warn!("Failed to configure TUN interface: {e}");
    }

    if config.mtu > 0 {
        if let Err(e) = set_mtu(&config.interface, config.mtu).await {
            tracing::warn!("Failed to set MTU (backup): {e}");
        }
    }

    // Add routes
    add_routes(&config, config_dir).await;

    // Start the TUN-to-SS proxy (blocks until SIGINT/SIGTERM)
    tracing::info!("Starting TUN-to-shadowsocks proxy");

    let config_for_tunnel = config.clone();
    let svr_cfg_for_tunnel = svr_cfg.clone();

    let mut tunnel_task = tokio::spawn(tunnel::run_tun_tproxy(
        tun_fd,
        config_for_tunnel,
        ctx,
        svr_cfg_for_tunnel,
    ));

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let result = tokio::select! {
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT, shutting down...");
            Ok(())
        }
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, shutting down...");
            Ok(())
        }
        result = &mut tunnel_task => {
            match result {
                Ok(Ok(())) => {
                    tracing::info!("Proxy exited normally");
                    Ok(())
                }
                Ok(Err(e)) => {
                    tracing::error!("Proxy error: {e}");
                    Err(e)
                }
                Err(e) => {
                    tracing::error!("Proxy task panicked: {e}");
                    Err(anyhow::anyhow!("Proxy task panicked: {e}"))
                }
            }
        }
    };

    // Stop plugin
    if let Some(mut p) = plugin_process {
        plugin::stop_plugin(&mut p).await;
    }

    result
}

/// Add routes from data/ and default_route/ relative to config_dir.
async fn add_routes(config: &config::Config, config_dir: &Path) {
    if !config.interface.is_empty() && (!config.gateway.is_empty() || !config.gateway6.is_empty()) {
        let dir = config_dir.join("data");
        tracing::info!(
            "Adding routes for interface: {} from {}",
            config.interface,
            dir.display()
        );
        if let Err(e) = route::add_routes_from_dir(
            &dir,
            &config.gateway,
            &config.gateway6,
            &config.interface,
            config.concurrency,
        )
        .await
        {
            tracing::error!("Error adding routes: {e}");
        }
    }

    if !config.default_interface.is_empty() && !config.default_gateway.is_empty() {
        let dir = config_dir.join("default_route");
        tracing::info!(
            "Adding routes for default interface: {} from {}",
            config.default_interface,
            dir.display()
        );
        if let Err(e) = route::add_routes_from_dir(
            &dir,
            &config.default_gateway,
            "",
            &config.default_interface,
            config.concurrency,
        )
        .await
        {
            tracing::error!("Error adding default routes: {e}");
        }
    }
}

async fn wait_for_interface(name: &str) {
    for i in 0..20 {
        if netlink::interface_exists(name).await {
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

async fn set_mtu(name: &str, mtu: u16) -> Result<()> {
    let name = name.to_string();
    netlink::with_handle(move |handle| async move {
        use futures::TryStreamExt;
        let mut links = handle.link().get().match_name(name.clone()).execute();
        if let Some(link) = links.try_next().await? {
            handle
                .link()
                .set(link.header.index)
                .mtu(mtu as u32)
                .execute()
                .await?;
        }
        Ok(())
    })
    .await
}

/// Create systemd-networkd config so networkd does not interfere with the TUN interface.
fn ensure_networkd_config(interface: &str) {
    if interface.is_empty() {
        return;
    }
    let path = format!("{NETWORKD_DIR}/99-ssroute.network");
    let content = format!(
        "\
[Match]
Name={interface}

[Network]
KeepConfiguration=yes
IgnoreCarrierLoss=yes

[Link]
Unmanaged=yes
"
    );
    if std::fs::read_to_string(&path).ok().as_deref() == Some(&content) {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(NETWORKD_DIR) {
        tracing::warn!("Failed to create {NETWORKD_DIR}: {e}");
        return;
    }
    match std::fs::write(&path, &content) {
        Ok(()) => tracing::info!("Created {path}"),
        Err(e) => tracing::warn!("Failed to write {path}: {e}"),
    }
}

///tell NM: "Don't touch this interface"
async fn setup_unmanaged_interface(iface_name: &str) -> Result<(), Box<dyn Error>> {
    // 1. Establish connection to the system D-Bus
    let connection = match Connection::system().await {
        Ok(conn) => conn,
        Err(_) => {
            tracing::info!("System D-Bus not found. Skipping NetworkManager integration.");
            return Ok(());
        }
    };

    // 2. Check if NM is active to avoid "Service Not Found" errors
    if !is_nm_running(&connection).await {
        tracing::info!("NetworkManager is not running. Nothing to do.");
        return Ok(());
    }

    // 3. Create proxy for the main NM object
    let nm_proxy = Proxy::new(
        &connection,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await?;

    tracing::info!("Waiting for NetworkManager to detect {iface_name}...");

    // 4. Polling: NM needs a moment to see the new kernel device
    let mut device_path = None;
    for _ in 0..20 {
        match nm_proxy
            .call::<&str, (&str,), zbus::zvariant::OwnedObjectPath>(
                "GetDeviceByIpIface",
                &(iface_name,),
            )
            .await
        {
            Ok(path) => {
                device_path = Some(path);
                break;
            }
            Err(_) => sleep(Duration::from_millis(150)).await,
        }
    }

    let path = device_path.ok_or_else(|| {
        format!(
            "Timeout: NM did not recognize {iface_name} within 3s",
        )
    })?;

    // 5. Create proxy for the specific device and set 'Managed' to false
    let device_proxy = Proxy::new(
        &connection,
        "org.freedesktop.NetworkManager",
        path,
        "org.freedesktop.NetworkManager.Device",
    )
    .await?;

    // Note: set_property handles the type wrapping automatically
    device_proxy.set_property("Managed", false).await?;

    tracing::info!("Interface {iface_name} is now UNMANAGED by NetworkManager.");
    Ok(())
}

/// Checks if NM is active on the D-Bus system bus
async fn is_nm_running(conn: &Connection) -> bool {
    let dbus_proxy = match Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    {
        Ok(p) => p,
        Err(_) => return false,
    };

    // zbus 4.x call syntax: <MethodName, BodyTuple, ReturnType>
    dbus_proxy
        .call::<&str, (&str,), bool>("NameHasOwner", &("org.freedesktop.NetworkManager",))
        .await
        .unwrap_or(false)
}
