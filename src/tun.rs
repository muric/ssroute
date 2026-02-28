use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{bail, Context, Result};

// Linux x86_64 ioctl constants for TUN devices.
// Used only in oneshot mode (persistent TUN). In daemon mode, shadowsocks-service
// creates the TUN device itself.
const TUNSETIFF: u64 = 0x400454ca;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const TUNSETPERSIST: u64 = 0x400454cb;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: u16,
}

/// Create a TUN interface with the given name.
///
/// If `persistent` is true, the interface survives after the process exits.
/// Returns None in this case (fd is closed after TUNSETPERSIST).
///
/// If `persistent` is false, returns the raw fd. The caller MUST keep it open —
/// closing the fd destroys the interface.
pub fn create_tun(name: &str, persistent: bool) -> Result<Option<OwnedFd>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("open /dev/net/tun")?;

    let fd = file.as_raw_fd();

    let mut ifr = IfReq {
        ifr_name: [0u8; 16],
        ifr_flags: IFF_TUN | IFF_NO_PI,
    };

    let name_bytes = name.as_bytes();
    if name_bytes.len() >= 16 {
        bail!("interface name too long: {name}");
    }
    ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    let ret = unsafe { nix::libc::ioctl(fd, TUNSETIFF, &ifr as *const IfReq) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        bail!("ioctl TUNSETIFF for {name}: {err}");
    }

    if persistent {
        let ret = unsafe { nix::libc::ioctl(fd, TUNSETPERSIST, 1 as nix::libc::c_int) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            bail!("ioctl TUNSETPERSIST for {name}: {err}");
        }
        tracing::info!("Interface {name} is now persistent");
        // fd is closed when `file` is dropped
        return Ok(None);
    }

    tracing::info!("Interface {name} created (non-persistent, fd kept open)");

    // Prevent the File from closing the fd — we transfer ownership to OwnedFd
    let raw_fd = file.as_raw_fd();
    std::mem::forget(file);
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    Ok(Some(owned))
}


/// Configure TUN interface: assign IP address (gateway/24), set MTU, bring up.
pub async fn configure_tun(name: &str, gateway: &str, mtu: u16) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .context("create netlink connection")?;
    let _conn = tokio::spawn(connection);

    // Find link by name
    use futures::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links
        .try_next()
        .await
        .context("netlink get link")?
        .with_context(|| format!("interface not found: {name}"))?;
    let index = link.header.index;

    // Parse gateway as IPv4
    let addr: std::net::Ipv4Addr = gateway
        .parse()
        .with_context(|| format!("invalid gateway IP: {gateway}"))?;

    // Add address (gateway/24)
    let result = handle
        .address()
        .add(index, std::net::IpAddr::V4(addr), 24)
        .execute()
        .await;

    match result {
        Ok(()) => {}
        Err(e) => {
            let err_str = format!("{e}");
            if err_str.contains("File exists") || err_str.contains("EEXIST") {
                tracing::warn!("IP {gateway} already set on interface {name}");
            } else {
                return Err(e).context("add address to interface");
            }
        }
    }

    // Set MTU
    if mtu > 0 {
        handle
            .link()
            .set(index)
            .mtu(mtu as u32)
            .execute()
            .await
            .with_context(|| format!("set MTU {mtu} on interface {name}"))?;
    }

    // Bring interface up
    handle
        .link()
        .set(index)
        .up()
        .execute()
        .await
        .with_context(|| format!("bring up interface {name}"))?;

    Ok(())
}
