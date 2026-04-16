use std::net::IpAddr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use futures::TryStreamExt;

/// Add a single route via netlink.
/// Returns Ok(()) if route added or already exists, Err only for real errors.
async fn add_route(
    handle: &rtnetlink::Handle,
    destination: &str,
    gateway: Option<IpAddr>,
    iface_index: u32,
) -> Result<()> {
    let (ip, prefix_len) = parse_destination(destination)?;

    match ip {
        IpAddr::V4(dest_ip) => {
            let mut builder = handle
                .route()
                .add()
                .v4()
                .destination_prefix(dest_ip, prefix_len)
                .output_interface(iface_index);

            if let Some(IpAddr::V4(gw_ip)) = gateway {
                builder = builder.gateway(gw_ip);
            }

            match builder.execute().await {
                Ok(()) => Ok(()),
                Err(e) if is_file_exists(&e) => {
                    // Route already exists - not an error
                    tracing::debug!("Route {destination} already exists, skipping");
                    Ok(())
                }
                Err(e) if gateway.is_some() => {
                    // If adding route with gateway fails, try without gateway (interface-only)
                    tracing::debug!("Route with gateway failed ({e}), trying without gateway");
                    match handle
                        .route()
                        .add()
                        .v4()
                        .destination_prefix(dest_ip, prefix_len)
                        .output_interface(iface_index)
                        .execute()
                        .await
                    {
                        Ok(()) => {
                            tracing::debug!("Successfully added IPv4 route {destination} on interface (no gateway)");
                            Ok(())
                        }
                        Err(e) if is_file_exists(&e) => {
                            tracing::debug!("Route {destination} already exists (interface-only), skipping");
                            Ok(())
                        }
                        Err(e) => Err(e).with_context(|| format!(
                            "netlink add_route (fallback): destination={destination}, iface_index={iface_index}"
                        )),
                    }
                }
                Err(e) => Err(e).with_context(|| {
                    format!(
                        "netlink add_route: destination={destination}, gateway={gateway:?}, iface_index={iface_index}"
                    )
                }),
            }
        }
        IpAddr::V6(dest_ip) => {
            let mut builder = handle
                .route()
                .add()
                .v6()
                .destination_prefix(dest_ip, prefix_len)
                .output_interface(iface_index);

            if let Some(IpAddr::V6(gw_ip)) = gateway {
                builder = builder.gateway(gw_ip);
            }

            match builder.execute().await {
                Ok(()) => Ok(()),
                Err(e) if is_file_exists(&e) => {
                    tracing::debug!("Route {destination} already exists, skipping");
                    Ok(())
                }
                Err(e) if gateway.is_some() => {
                    // If adding route with gateway fails, try without gateway (interface-only)
                    tracing::debug!("Route with gateway failed ({e}), trying without gateway");
                    match handle
                        .route()
                        .add()
                        .v6()
                        .destination_prefix(dest_ip, prefix_len)
                        .output_interface(iface_index)
                        .execute()
                        .await
                    {
                        Ok(()) => {
                            tracing::debug!("Successfully added IPv6 route {destination} on interface (no gateway)");
                            Ok(())
                        }
                        Err(e) if is_file_exists(&e) => {
                            tracing::debug!("Route {destination} already exists (interface-only), skipping");
                            Ok(())
                        }
                        Err(e) => Err(e).with_context(|| format!(
                            "netlink add_route (fallback): destination={destination}, iface_index={iface_index}"
                        )),
                    }
                }
                Err(e) => Err(e).with_context(|| format!(
                    "netlink add_route: destination={destination}, gateway={gateway:?}, iface_index={iface_index}"
                )),
            }
        }
    }
}

/// Check if error is "file already exists" (os error 17 / EEXIST).
///
/// Prefer structured inspection of the error chain (io::ErrorKind, raw_os_error)
/// and only fall back to substring checks on the formatted message.
fn is_file_exists<E>(e: &E) -> bool
where
    E: std::error::Error + 'static,
{
    // Numeric code for EEXIST on Unix-like systems.
    const EEXIST: i32 = 17;

    // Walk the error chain looking for an underlying io::Error with
    // Either ErrorKind::AlreadyExists or the EEXIST raw OS code.
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::AlreadyExists {
                return true;
            }
            if io_err.raw_os_error() == Some(EEXIST) {
                return true;
            }
        }
        current = err.source();
    }

    // Fallback: match common substrings in the formatted message.
    // This keeps compatibility with environments where only the textual
    // representation is available.
    let s = e.to_string().to_lowercase();
    s.contains("file exists") || s.contains("eexist") || s.contains("error 17")
}

/// Parse a destination string as either a CIDR or a bare IP (treated as /32 for IPv4 or /128 for IPv6).
fn parse_destination(dest: &str) -> Result<(IpAddr, u8)> {
    if let Some((ip_str, prefix_str)) = dest.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("invalid IP in CIDR: {dest}"))?;
        let prefix: u8 = prefix_str
            .parse()
            .with_context(|| format!("invalid prefix in CIDR: {dest}"))?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            bail!("prefix length {prefix} exceeds {max_prefix} in: {dest}");
        }
        Ok((ip, prefix))
    } else {
        let ip: IpAddr = dest
            .parse()
            .with_context(|| format!("invalid IP address: {dest}"))?;
        let default_prefix = if ip.is_ipv4() { 32 } else { 128 };
        Ok((ip, default_prefix))
    }
}

/// Look up a network interface index by name via netlink.
async fn get_iface_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links
        .try_next()
        .await
        .context("netlink get link")?
        .with_context(|| format!("interface not found: {name}"))?;
    Ok(link.header.index)
}

/// Add routes from all .json files in a directory.
///
/// Each .json file contains a JSON array of IP/CIDR strings.
/// Routes are added in parallel, limited by `concurrency`.
pub async fn add_routes_from_dir(
    dir: &Path,
    gateway: &str,
    gateway6: &str,
    iface_name: &str,
    _concurrency: usize,
) -> Result<()> {
    let dir_path = dir;
    if !dir_path.exists() {
        tracing::info!("Directory {} does not exist — skipping", dir.display());
        return Ok(());
    }

    let (connection, handle, _) =
        rtnetlink::new_connection().context("create netlink connection for routes")?;
    let _conn = tokio::spawn(connection);

    let iface_index = get_iface_index(&handle, iface_name).await.map_err(|e| {
        let err_str = format!("{e}");
        if err_str.contains("not found") || err_str.contains("Link not found") {
            anyhow::anyhow!(
                "interface '{iface_name}' does not exist — check 'interface' or 'default_interface' in config"
            )
        } else {
            e
        }
    })?;

    let gw: Option<IpAddr> = if !gateway.is_empty() {
        Some(
            gateway
                .parse()
                .with_context(|| format!("invalid gateway IP: {gateway}"))?,
        )
    } else {
        None
    };

    let gw6: Option<IpAddr> = if !gateway6.is_empty() {
        Some(
            gateway6
                .parse()
                .with_context(|| format!("invalid gateway6 IP: {gateway6}"))?,
        )
    } else {
        None
    };

    tracing::info!("Using route gateways: gw={:?}, gw6={:?}", gw, gw6);

    let mut json_files: Vec<String> = Vec::new();
    let entries =
        std::fs::read_dir(dir_path).with_context(|| format!("read directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                json_files.push(name.to_string());
            }
        }
    }

    if json_files.is_empty() {
        tracing::info!("No route files found in {} — skipping", dir.display());
        return Ok(());
    }

    json_files.sort();

    for file_name in &json_files {
        tracing::info!("Processing: {file_name}");

        let file_path = dir_path.join(file_name);
        let destinations: Vec<String> = {
            let data = match std::fs::read_to_string(&file_path) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("Error reading file {file_name}: {e}");
                    continue;
                }
            };
            match serde_json::from_str(&data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("Error parsing JSON {file_name}: {e}");
                    continue;
                }
            }
        };

        for dest in destinations {
            let is_ipv4 = match dest.split('/').next() {
                Some(ip_part) if !ip_part.is_empty() => !ip_part.contains(':'),
                _ => {
                    tracing::error!("Invalid destination format {dest}");
                    continue;
                }
            };

            let route_gw: Option<IpAddr> = if is_ipv4 {
                gw.filter(|g| g.is_ipv4())
            } else if iface_name.contains("tun") {
                tracing::debug!(
                    "TUN interface detected, using interface-only IPv6 route for {dest}"
                );
                None
            } else {
                gw6.or_else(|| gw.filter(|g| g.is_ipv6()))
            };

            if let Err(e) = add_route(&handle, &dest, route_gw, iface_index).await {
                tracing::error!("Failed to add route {dest}: {e}");
                bail!("Failed to add route {dest}: {e}");
            }
        }
    }

    Ok(())
}
