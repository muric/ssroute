use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use futures::stream::{self, StreamExt};
use futures::TryStreamExt;

use crate::stats::{classify_error_str, Stats};

/// Add a single route via netlink.
async fn add_route(
    handle: &rtnetlink::Handle,
    destination: &str,
    gateway: IpAddr,
    iface_index: u32,
) -> Result<()> {
    let (ip, prefix_len) = parse_destination(destination)?;

    match (ip, gateway) {
        (IpAddr::V4(dest_ip), IpAddr::V4(gw_ip)) => {
            handle
                .route()
                .add()
                .v4()
                .destination_prefix(dest_ip, prefix_len)
                .gateway(gw_ip)
                .output_interface(iface_index)
                .execute()
                .await
                .with_context(|| format!("add route {destination} via {gateway} dev index {iface_index}"))?;
        }
        (IpAddr::V6(dest_ip), IpAddr::V6(gw_ip)) => {
            handle
                .route()
                .add()
                .v6()
                .destination_prefix(dest_ip, prefix_len)
                .gateway(gw_ip)
                .output_interface(iface_index)
                .execute()
                .await
                .with_context(|| format!("add route {destination} via {gateway} dev index {iface_index}"))?;
        }
        _ => {
            bail!("IP version mismatch: destination {ip} and gateway {gateway} must be the same IP version");
        }
    }

    Ok(())
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
    concurrency: usize,
    debug: bool,
    stats: &Arc<Stats>,
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
                "interface '{}' does not exist — check 'interface' or 'default_interface' in config",
                iface_name
            )
        } else {
            e
        }
    })?;

    let gw: Option<IpAddr> = if !gateway.is_empty() {
        Some(gateway.parse().with_context(|| format!("invalid gateway IP: {gateway}"))?)
    } else {
        None
    };

    let gw6: Option<IpAddr> = if !gateway6.is_empty() {
        Some(gateway6.parse().with_context(|| format!("invalid gateway6 IP: {gateway6}"))?)
    } else {
        None
    };

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
        let data = match std::fs::read_to_string(&file_path) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Error reading file {file_name}: {e}");
                continue;
            }
        };

        let destinations: Vec<String> = match serde_json::from_str(&data) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Error parsing JSON {file_name}: {e}");
                continue;
            }
        };

        let handle_ref = &handle;
        let stats_ref = &stats;

        stream::iter(destinations.into_iter())
            .for_each_concurrent(concurrency, |dest| async move {
                // Determine which gateway to use based on destination IP version
                let (dest_ip, _) = match parse_destination(&dest) {
                    Ok((ip, prefix)) => (ip, prefix),
                    Err(e) => {
                        tracing::error!("Error parsing destination {dest}: {e}");
                        stats_ref.add_error("parse_error");
                        return;
                    }
                };

                let route_gw = if dest_ip.is_ipv4() {
                    match gw {
                        Some(g) if g.is_ipv4() => g,
                        _ => {
                            tracing::error!("No IPv4 gateway configured for IPv4 destination {dest}");
                            stats_ref.add_error("no_ipv4_gateway");
                            return;
                        }
                    }
                } else {
                    match gw6 {
                        Some(g) if g.is_ipv6() => g,
                        _ => {
                            tracing::error!("No IPv6 gateway configured for IPv6 destination {dest}");
                            stats_ref.add_error("no_ipv6_gateway");
                            return;
                        }
                    }
                };

                match add_route(handle_ref, &dest, route_gw, iface_index).await {
                    Ok(()) => {
                        stats_ref.add_success();
                    }
                    Err(e) => {
                        let err_str = format!("{e}");
                        let err_type = classify_error_str(&err_str);
                        match err_type {
                            "file_exists" => {
                                stats_ref.add_already_exist(format!(
                                    "{dest} via {gateway} dev {iface_name}"
                                ));
                            }
                            "no_such_device" => {
                                tracing::error!(
                                    "interface '{}' disappeared during route loading",
                                    iface_name
                                );
                            }
                            _ => {
                                stats_ref.add_error(err_type);
                                if debug {
                                    tracing::error!(
                                        "Error adding route for {dest} via {gateway} dev {iface_name}: {e}"
                                    );
                                }
                            }
                        }
                    }
                }
            })
            .await;
    }

    Ok(())
}
