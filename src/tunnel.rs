//! TUN-to-shadowsocks proxy using native tokio TCP sockets.
//!
//! Reads raw IP packets from a TUN interface, demultiplexes TCP/UDP,
//! and forwards them through encrypted shadowsocks streams.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::time::Duration;

use anyhow::{bail, Result};
use shadowsocks::config::ServerConfig;
use shadowsocks::context::SharedContext;
use shadowsocks::net::TcpStream as SsTcpStream;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, timeout_at, Instant};

use crate::config::Config;

/// Maximum concurrent connections before eviction.
const MAX_CONNECTIONS: usize = 4096;

// ── IP/TCP/UDP packet parsing ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct IpHeader {
    version: u8,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8, // 6=TCP, 17=UDP
    header_len: u8,
    src_port: u16,
    dst_port: u16,
}

fn ipv4_addr_from_bytes(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() < 4 {
        return None;
    }
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn ipv6_addr_from_bytes(bytes: &[u8]) -> Option<Ipv6Addr> {
    if bytes.len() < 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    Some(Ipv6Addr::from(buf))
}

/// Parse IP + TCP/UDP header from a raw packet.
fn parse_ip_packet(buf: &[u8]) -> Option<IpHeader> {
    if buf.len() < 40 {
        return None;
    }

    let first = buf[0];
    let version = first >> 4;
    let ihl = (first & 0x0f) * 4;

    if ihl < 20 || ihl as usize > buf.len() {
        return None;
    }

    let protocol = buf[9];
    if protocol != 6 && protocol != 17 {
        return None;
    }

    // Need enough bytes for transport header
    let needed = match protocol {
        6 => 40,  // IPv4(20) + TCP(20)
        17 => 28, // IPv4(20) + UDP(8)
        _ => return None,
    };
    if buf.len() < needed as usize {
        return None;
    }

    let (src, dst) = match version {
        4 => (
            IpAddr::V4(ipv4_addr_from_bytes(&buf[12..16])?),
            IpAddr::V4(ipv4_addr_from_bytes(&buf[16..20])?),
        ),
        6 => (
            IpAddr::V6(ipv6_addr_from_bytes(&buf[8..24])?),
            IpAddr::V6(ipv6_addr_from_bytes(&buf[24..40])?),
        ),
        _ => return None,
    };

    let transport_start = ihl as usize;
    let sport = u16::from_be_bytes(buf[transport_start..transport_start + 2].try_into().ok()?);
    let dport = u16::from_be_bytes(
        buf[transport_start + 2..transport_start + 4]
            .try_into()
            .ok()?,
    );

    Some(IpHeader {
        version,
        src,
        dst,
        protocol,
        header_len: ihl,
        src_port: sport,
        dst_port: dport,
    })
}

// ── Connection tracking ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct ConnKey {
    version: u8,
    src_ip: u128,
    dst_ip: u128,
    sport: u16,
    dport: u16,
    proto: u8,
}

impl ConnKey {
    fn from_ip(h: &IpHeader, sport: u16, dport: u16) -> Self {
        Self {
            version: h.version,
            src_ip: ip_to_u128(h.src),
            dst_ip: ip_to_u128(h.dst),
            sport,
            dport,
            proto: h.protocol,
        }
    }

    fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            sport: self.dport,
            dport: self.sport,
            ..*self
        }
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v) => u128::from(u32::from(v)),
        IpAddr::V6(v) => u128::from_be_bytes(v.octets()),
    }
}

/// Active connection with stream and bookkeeping.
struct ActiveConn {
    stream: ProxyClientStream<SsTcpStream>,
    last_active: std::time::Instant,
}

// ── IP response packet builder ───────────────────────────────────

/// Build a response IP packet by swapping src/dst addresses and ports.
fn build_response_packet(
    payload: &[u8],
    original: &IpHeader,
    rev_key: &ConnKey,
) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(payload.len() + 60);

    match original.version {
        4 => {
            let dst_ip = match &original.dst {
                IpAddr::V4(v) => v.octets(),
                _ => bail!("expected IPv4, got IPv6"),
            };
            let src_ip = match &original.src {
                IpAddr::V4(v) => v.octets(),
                _ => bail!("expected IPv4, got IPv6"),
            };

            let total_len = (payload.len() + 20 + if original.protocol == 6 { 20 } else { 8 }) as u16;
            packet.extend_from_slice(&[
                0x45,                    // version=4, IHL=5
                0x00,                    // ToS
                (total_len >> 8) as u8, (total_len & 0xff) as u8,
                0x00, 0x00,              // identification
                0x40, 0x00,              // DF flag
                64,                      // TTL
                original.protocol,
                0x00, 0x00,              // checksum (0 = kernel computes)
            ]);
            packet.extend_from_slice(&dst_ip); // src = TUN IP
            packet.extend_from_slice(&src_ip); // dst = server IP

            match original.protocol {
                6 => {
                    let sport = rev_key.sport.to_be_bytes();
                    let dport = rev_key.dport.to_be_bytes();
                    packet.extend_from_slice(&[
                        sport[0], sport[1],
                        dport[0], dport[1],
                        0x00, 0x00, 0x00, 0x00,
                        0x50, 0x00,
                        0xff, 0xff,
                        0x00, 0x00,
                        0x00, 0x00,
                    ]);
                }
                17 => {
                    let sport = rev_key.sport.to_be_bytes();
                    let dport = rev_key.dport.to_be_bytes();
                    let udp_len = (8 + payload.len()) as u16;
                    packet.extend_from_slice(&[
                        sport[0], sport[1],
                        dport[0], dport[1],
                        (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
                        0x00, 0x00,
                    ]);
                }
                _ => bail!("unsupported protocol: {}", original.protocol),
            }

            packet.extend_from_slice(payload);
        }
        6 => {
            let src_ip_raw = rev_key.src_ip.to_be_bytes();
            let dst_ip_raw = rev_key.dst_ip.to_be_bytes();
            let payload_len = payload.len();

            packet.extend_from_slice(&[
                0x60, 0x00, 0x00, 0x00,
                (payload_len >> 8) as u8, (payload_len & 0xff) as u8,
                original.protocol,
                64, // hop limit
            ]);
            packet.extend_from_slice(&src_ip_raw);
            packet.extend_from_slice(&dst_ip_raw);

            match original.protocol {
                6 => {
                    let sport = rev_key.sport.to_be_bytes();
                    let dport = rev_key.dport.to_be_bytes();
                    packet.extend_from_slice(&[
                        sport[0], sport[1],
                        dport[0], dport[1],
                        0x00, 0x00, 0x00, 0x00,
                        0x50, 0x00,
                        0xff, 0xff,
                        0x00, 0x00,
                        0x00, 0x00,
                    ]);
                }
                17 => {
                    let sport = rev_key.sport.to_be_bytes();
                    let dport = rev_key.dport.to_be_bytes();
                    let udp_len = (8 + payload_len) as u16;
                    packet.extend_from_slice(&[
                        sport[0], sport[1],
                        dport[0], dport[1],
                        (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
                        0x00, 0x00,
                    ]);
                }
                _ => bail!("unsupported protocol: {}", original.protocol),
            }

            packet.extend_from_slice(payload);
        }
        _ => bail!("unsupported IP version: {}", original.version),
    }

    Ok(packet)
}

// ── Main tunnel loop ─────────────────────────────────────────────

/// Run the TUN-to-shadowsocks proxy.
pub async fn run_tun_tproxy(
    tun_fd: OwnedFd,
    _config: Config,
    ctx: SharedContext,
    svr_cfg: ServerConfig,
) -> Result<()> {
    // Convert OwnedFd to a std::fs::File for blocking read() calls.
    let tun_fd_raw = tun_fd.as_raw_fd();
    let tun_file = unsafe { std::fs::File::from_raw_fd(tun_fd_raw) };
    // Forget the OwnedFd so the file owns the fd
    std::mem::forget(tun_fd);

    let mut connections: HashMap<ConnKey, ActiveConn> = HashMap::new();
    let mut read_buf = [0u8; 65536];

    loop {
        // Read next IP packet from TUN (blocking syscall → spawn_blocking)
        let mut tun_clone = tun_file.try_clone()?;
        let n = match tokio::task::spawn_blocking(move || tun_clone.read(&mut read_buf))
            .await
            .unwrap_or(Ok(0))
        {
            Ok(0) => break, // EOF
            Ok(n) if n > 0 => n,
            Ok(_) => continue,
            Err(e) => {
                tracing::error!("TUN read error: {e}");
                continue;
            }
        };

        let packet = &read_buf[..n];

        let hdr = match parse_ip_packet(packet) {
            Some(h) => h,
            None => continue,
        };

        let transport_start = hdr.header_len as usize;
        let payload = &packet[transport_start..];
        let rev_key = ConnKey::from_ip(&hdr, hdr.src_port, hdr.dst_port).reversed();

        match connections.get_mut(&rev_key) {
            Some(conn) => {
                conn.last_active = std::time::Instant::now();

                if !payload.is_empty() {
                    if let Err(e) = conn.stream.write_all(payload).await {
                        tracing::warn!("Stream write failed: {e}, removing connection");
                        connections.remove(&rev_key);
                        continue;
                    }
                }

                read_and_forward_responses(
                    &mut conn.stream,
                    &hdr,
                    &rev_key,
                )
                .await;
            }
            None => {
                let target = match (hdr.version, &hdr.dst, hdr.dst_port) {
                    (4, IpAddr::V4(d), p) => Address::SocketAddress(SocketAddr::from((*d, p))),
                    (6, IpAddr::V6(d), p) => Address::SocketAddress(SocketAddr::from((*d, p))),
                    _ => continue,
                };

                // Evict oldest if at capacity
                if connections.len() >= MAX_CONNECTIONS {
                    if let Some(oldest) = connections
                        .iter()
                        .min_by_key(|(_, c)| c.last_active)
                        .map(|(k, _)| *k)
                    {
                        connections.remove(&oldest);
                        tracing::debug!("Evicted oldest connection (limit: {MAX_CONNECTIONS})");
                    }
                }

                let payload = payload.to_vec();
                match timeout(
                    Duration::from_secs(10),
                    ProxyClientStream::connect(ctx.clone(), &svr_cfg, target.clone()),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        tracing::debug!(
                            "New connection: {}:{} → {}",
                            hdr.dst,
                            hdr.dst_port,
                            svr_cfg.addr(),
                        );

                        if !payload.is_empty() {
                            if let Err(e) = stream.write_all(&payload).await {
                                tracing::warn!("Initial write failed: {e}");
                                continue;
                            }
                        }

                        connections.insert(
                            rev_key,
                            ActiveConn {
                                stream,
                                last_active: std::time::Instant::now(),
                            },
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Failed to create connection to {}: {e}", target);
                    }
                    Err(_) => {
                        tracing::warn!("Connection to {} timed out", target);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Try to read response data from the encrypted stream and write to TUN.
/// Uses a 0ms timeout to avoid blocking if no data is available.
async fn read_and_forward_responses(
    stream: &mut ProxyClientStream<SsTcpStream>,
    hdr: &IpHeader,
    rev_key: &ConnKey,
) {
    let mut resp_buf = [0u8; 32768];
    let deadline = Instant::now() + Duration::from_millis(1);
    let n = match timeout_at(deadline, stream.read(&mut resp_buf)).await {
        Ok(Ok(0)) => return,
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::warn!("Response read failed: {e}");
            return;
        }
        Err(_) => return, // timeout
    };

    let resp_data = &resp_buf[..n];

    let response_pkt = match build_response_packet(resp_data, hdr, rev_key) {
        Ok(pkt) => pkt,
        Err(e) => {
            tracing::warn!("Failed to build response packet: {e}");
            return;
        }
    };

    // Write to TUN — open and write, fd stays open
    let mut tun_file = std::fs::File::open("/dev/net/tun")
        .expect("TUN fd should be open");
    if let Err(e) = tun_file.write_all(&response_pkt) {
        tracing::warn!("Failed to write response to TUN: {e}");
    }
}

