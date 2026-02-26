use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use futures::TryStreamExt;

use crate::stats::{classify_error_str, Stats};

const MAIN_ROUTE_DIR: &str = "data";
const DEFAULT_ROUTE_DIR: &str = "default_route";

pub fn main_route_dir() -> &'static str {
    MAIN_ROUTE_DIR
}

pub fn default_route_dir() -> &'static str {
    DEFAULT_ROUTE_DIR
}

/// Add a single route via netlink.
async fn add_route(
    handle: &rtnetlink::Handle,
    destination: &str,
    gateway: Ipv4Addr,
    iface_index: u32,
) -> Result<()> {
    let (ip, prefix_len) = parse_destination(destination)?;

    let route_msg = handle
        .route()
        .add()
        .v4()
        .destination_prefix(ip, prefix_len)
        .gateway(gateway)
        .output_interface(iface_index);

    route_msg.execute().await.with_context(|| {
        format!("add route {destination} via {gateway} dev index {iface_index}")
    })?;

    Ok(())
}

/// Parse a destination string as either a CIDR or a bare IP (treated as /32).
fn parse_destination(dest: &str) -> Result<(Ipv4Addr, u8)> {
    if let Some((ip_str, prefix_str)) = dest.split_once('/') {
        let ip: Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("invalid IP in CIDR: {dest}"))?;
        let prefix: u8 = prefix_str
            .parse()
            .with_context(|| format!("invalid prefix in CIDR: {dest}"))?;
        Ok((ip, prefix))
    } else {
        let ip: Ipv4Addr = dest
            .parse()
            .with_context(|| format!("invalid IP address: {dest}"))?;
        Ok((ip, 32))
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
    dir: &str,
    gateway: &str,
    iface_name: &str,
    concurrency: usize,
    debug: bool,
    stats: &Arc<Stats>,
) -> Result<()> {
    let dir_path = Path::new(dir);
    if !dir_path.exists() {
        tracing::info!("Directory {dir} does not exist — skipping");
        return Ok(());
    }

    // Create netlink connection
    let (connection, handle, _) = rtnetlink::new_connection()
        .context("create netlink connection for routes")?;
    tokio::spawn(connection);

    // Look up interface
    let iface_index = match get_iface_index(&handle, iface_name).await {
        Ok(idx) => idx,
        Err(e) => {
            let err_str = format!("{e}");
            if err_str.contains("not found") || err_str.contains("Link not found") {
                tracing::error!(
                    "Configuration error: interface '{}' does not exist. Check 'interface' or 'default_interface' in config.",
                    iface_name
                );
                std::process::exit(1);
            }
            return Err(e);
        }
    };

    let gw: Ipv4Addr = gateway
        .parse()
        .with_context(|| format!("invalid gateway IP: {gateway}"))?;

    // Collect .json files
    let mut json_files: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir_path)
        .with_context(|| format!("read directory {dir}"))?;

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
        tracing::info!("No route files found in {dir} — skipping");
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
                match add_route(handle_ref, &dest, gw, iface_index).await {
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
                                    "Configuration error: interface '{}' does not exist. Check 'interface' or 'default_interface' in config.",
                                    iface_name
                                );
                                std::process::exit(1);
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
