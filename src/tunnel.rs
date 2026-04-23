//! TUN-to-shadowsocks proxy using native tokio TCP/UDP sockets.
//!
//! Reads raw IP packets from a TUN interface, demultiplexes TCP/UDP,
//! and forwards them through encrypted shadowsocks streams.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use shadowsocks::config::ServerConfig;
use shadowsocks::context::SharedContext;
use shadowsocks::net::TcpStream as SsTcpStream;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use shadowsocks::relay::udprelay::proxy_socket::ProxySocket;

use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::config::Config;

// ── Checksum computation (standard RFC 1071 one's complement) ──

/// Compute IPv4 header checksum.
fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        sum += (data[i] as u32) << 8;
        if i + 1 < data.len() {
            sum += data[i + 1] as u32;
            i += 2;
        } else {
            i += 1;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Compute TCP/UDP checksum with pseudo-header.
fn tcp_checksum(
    src: &IpAddr,
    dst: &IpAddr,
    protocol: u8,
    data: &[u8], // TCP header (with checksum=0 at offset 16-17) + payload
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source IP + dest IP + protocol + TCP length
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum += u32::from_be_bytes(s.octets());
            sum += u32::from_be_bytes(d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            for b in s.octets().chunks(2) {
                sum += u32::from(b[0]) << 8 | u32::from(b[1]);
            }
            for b in d.octets().chunks(2) {
                sum += u32::from(b[0]) << 8 | u32::from(b[1]);
            }
        }
        _ => unreachable!("mixed IPv4/IPv6"),
    }
    sum += u32::from(protocol) << 8;
    sum += u32::from(data.len() as u16);

    // TCP header + payload (checksum field at offset 16-17 is already 0)
    let mut i = 0;
    while i < data.len() {
        sum += u32::from(data[i]) << 8;
        if i + 1 < data.len() {
            sum += u32::from(data[i + 1]);
            i += 2;
        } else {
            i += 1;
        }
    }

    // Fold carries
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Maximum concurrent connections before eviction.
const MAX_CONNECTIONS: usize = 4096;

// ── IP/TCP/UDP packet parsing ──────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct IpHeader {
    version: u8,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8, // 6=TCP, 17=UDP
    header_len: u8,
    src_port: u16,
    dst_port: u16,
    // TCP fields (only valid for protocol == 6)
    pub tcp_flags: u8,
    pub tcp_seq: u32,
    #[allow(dead_code)]
    tcp_ack: u32,
}

// TCP flag constants
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;

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
    if buf.is_empty() {
        return None;
    }

    let first = buf[0];
    let version = first >> 4;

    match version {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<IpHeader> {
    let ihl = (buf[0] & 0x0f) * 4;
    if ihl < 20 || ihl as usize > buf.len() {
        return None;
    }

    let protocol = buf[9];
    if protocol != 6 && protocol != 17 {
        return None;
    }

    let transport_needed = if protocol == 6 { 20 } else { 8 };
    let needed = ihl as usize + transport_needed;
    if buf.len() < needed {
        return None;
    }

    let src = IpAddr::V4(ipv4_addr_from_bytes(&buf[12..16])?);
    let dst = IpAddr::V4(ipv4_addr_from_bytes(&buf[16..20])?);

    let th = ihl as usize;
    let sport = u16::from_be_bytes(buf[th..th + 2].try_into().ok()?);
    let dport = u16::from_be_bytes(
        buf[th + 2..th + 4]
            .try_into()
            .ok()?,
    );

    // TCP header fields (flags, seq, ack) — always present in TCP header
    let (tcp_flags, tcp_seq, tcp_ack) = if protocol == 6 && buf.len() >= ihl as usize + 20 {
        let seq = u32::from_be_bytes(buf[th + 4..th + 8].try_into().ok()?);
        let ack = u32::from_be_bytes(buf[th + 8..th + 12].try_into().ok()?);
        let flags = buf[th + 13];
        (flags, seq, ack)
    } else {
        (0, 0, 0)
    };

    Some(IpHeader {
        version: 4,
        src,
        dst,
        protocol,
        header_len: ihl,
        src_port: sport,
        dst_port: dport,
        tcp_flags,
        tcp_seq,
        tcp_ack,
    })
}

fn parse_ipv6(buf: &[u8]) -> Option<IpHeader> {
    // IPv6 base header is always 40 bytes, no IHL field
    let protocol = buf[4]; // Next header field at offset 4
    if protocol != 6 && protocol != 17 {
        return None;
    }

    let transport_needed = if protocol == 6 { 20 } else { 8 }; // TCP or UDP
    if buf.len() < 40 + transport_needed {
        return None;
    }

    let src = IpAddr::V6(ipv6_addr_from_bytes(&buf[8..24])?);
    let dst = IpAddr::V6(ipv6_addr_from_bytes(&buf[24..40])?);

    let th = 40;
    let sport = u16::from_be_bytes(buf[th..th + 2].try_into().ok()?);
    let dport = u16::from_be_bytes(buf[th + 2..th + 4].try_into().ok()?);

    // TCP header fields (flags, seq, ack)
    let (tcp_flags, tcp_seq, tcp_ack) = if protocol == 6 && buf.len() >= 40 + 20 {
        let seq = u32::from_be_bytes(buf[th + 4..th + 8].try_into().ok()?);
        let ack = u32::from_be_bytes(buf[th + 8..th + 12].try_into().ok()?);
        let flags = buf[th + 13];
        (flags, seq, ack)
    } else {
        (0, 0, 0)
    };

    Some(IpHeader {
        version: 6,
        src,
        dst,
        protocol,
        header_len: 40,
        src_port: sport,
        dst_port: dport,
        tcp_flags,
        tcp_seq,
        tcp_ack,
    })
}

// ── Connection tracking ────────────────────────────────────────

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

/// Active TCP connection.
struct TcpConn {
    write_half: tokio::io::WriteHalf<ProxyClientStream<SsTcpStream>>,
    last_active: std::time::Instant,
    client_seq: u32,    // Client's current sequence number (starts at ISN)
}

/// Metadata for a UDP connection (needed to build response packets).
#[derive(Clone)]
struct UdpConnMeta {
    hdr: IpHeader,
    rev_key: ConnKey,
}

// ── IP response packet builder ─────────────────────────────────

/// Build a TCP response IP packet with explicit seq/ack numbers.
fn build_tcp_response_packet(
    payload: &[u8],
    original: &IpHeader,
    rev_key: &ConnKey,
    server_seq: u32,
    client_ack: u32,
) -> Result<Vec<u8>> {
    let original_flags = original.tcp_flags;
    // Response flags: if SYN was set, SYN+ACK; otherwise PSH+ACK
    let resp_flags = if original_flags & TCP_SYN != 0 {
        TCP_SYN | TCP_ACK
    } else {
        TCP_PSH | TCP_ACK
    };
    let transport_hdr_len = 20;

    match original.version {
        4 => build_tcp_ipv4_packet(payload, original, rev_key, transport_hdr_len, resp_flags, server_seq, client_ack),
        6 => build_tcp_ipv6_packet(payload, original, rev_key, transport_hdr_len, resp_flags, server_seq, client_ack),
        v => bail!("unsupported IP version: {v}"),
    }
}

/// Build a response IP packet by swapping src/dst addresses and ports.
fn build_response_packet(
    payload: &[u8],
    original: &IpHeader,
    rev_key: &ConnKey,
) -> Result<Vec<u8>> {
    match original.protocol {
        6 => build_tcp_response_packet(payload, original, rev_key, 0, 0),
        17 => build_udp_response_packet(payload, original, rev_key),
        v => bail!("unsupported protocol: {v}"),
    }
}

fn build_udp_response_packet(
    payload: &[u8],
    hdr: &IpHeader,
    rev: &ConnKey,
) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(payload.len() + if hdr.version == 4 { 28 } else { 52 });

    match hdr.version {
        4 => build_udp_ipv4(&mut packet, payload, hdr, rev)?,
        6 => build_udp_ipv6(&mut packet, payload, hdr, rev)?,
        v => bail!("unsupported IP version: {v}"),
    }
    Ok(packet)
}

fn build_tcp_ipv4_packet(
    payload: &[u8],
    hdr: &IpHeader,
    rev: &ConnKey,
    transport_hdr_len: usize,
    tcp_flags: u8,
    seq: u32,
    ack: u32,
) -> Result<Vec<u8>> {
    let dst_ip = match &hdr.dst {
        IpAddr::V4(v) => v.octets(),
        _ => bail!("expected IPv4, got IPv6"),
    };
    let src_ip = match &hdr.src {
        IpAddr::V4(v) => v.octets(),
        _ => bail!("expected IPv4, got IPv6"),
    };

    let total_len = (payload.len() + 20 + transport_hdr_len) as u16;

    // Build IP header with checksum field = 0
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.extend_from_slice(&[
        0x45,                // version=4, IHL=5
        0x00,                // ToS
        (total_len >> 8) as u8, (total_len & 0xff) as u8,
        0x00, 0x00,          // identification
        0x40, 0x00,          // DF flag
        64,                  // TTL
        hdr.protocol,
        0x00, 0x00,          // checksum placeholder
    ]);
    pkt.extend_from_slice(&dst_ip);
    pkt.extend_from_slice(&src_ip);

    // Compute IPv4 header checksum (over first 20 bytes with checksum=0)
    let ip_checksum = ipv4_checksum(&pkt);
    pkt[10] = (ip_checksum >> 8) as u8;
    pkt[11] = (ip_checksum & 0xff) as u8;

    // Build TCP header placeholder (checksum = 0) then payload
    extend_tcp_response_header(&mut pkt, rev, tcp_flags, seq, ack);
    pkt.extend_from_slice(payload);

    // Compute TCP checksum (over pseudo-header + TCP header + payload)
    let tcp_cksum = tcp_checksum(&hdr.src, &hdr.dst, hdr.protocol, &pkt[20..]);
    pkt[36] = (tcp_cksum >> 8) as u8;
    pkt[37] = (tcp_cksum & 0xff) as u8;

    Ok(pkt)
}

fn build_tcp_ipv6_packet(
    payload: &[u8],
    hdr: &IpHeader,
    rev: &ConnKey,
    transport_hdr_len: usize,
    tcp_flags: u8,
    seq: u32,
    ack: u32,
) -> Result<Vec<u8>> {
    let src_ip_raw = rev.src_ip.to_be_bytes();
    let dst_ip_raw = rev.dst_ip.to_be_bytes();
    let ipv6_payload_len = (transport_hdr_len + payload.len()) as u16;

    let mut pkt = Vec::with_capacity((ipv6_payload_len + 40) as usize);
    pkt.extend_from_slice(&[
        0x60, 0x00, 0x00, 0x00,
        (ipv6_payload_len >> 8) as u8, (ipv6_payload_len & 0xff) as u8,
        hdr.protocol,
        64, // hop limit
    ]);
    pkt.extend_from_slice(&src_ip_raw);
    pkt.extend_from_slice(&dst_ip_raw);
    extend_tcp_response_header(&mut pkt, rev, tcp_flags, seq, ack);
    pkt.extend_from_slice(payload);

    // Compute TCP checksum (mandatory for IPv6)
    let tcp_cksum = tcp_checksum(&hdr.src, &hdr.dst, hdr.protocol, &pkt[40..]);
    pkt[56] = (tcp_cksum >> 8) as u8;
    pkt[57] = (tcp_cksum & 0xff) as u8;

    Ok(pkt)
}

fn build_udp_ipv4(
    buf: &mut Vec<u8>,
    payload: &[u8],
    hdr: &IpHeader,
    rev: &ConnKey,
) -> Result<()> {
    let dst_ip = match &hdr.dst {
        IpAddr::V4(v) => v.octets(),
        _ => bail!("expected IPv4, got IPv6"),
    };
    let src_ip = match &hdr.src {
        IpAddr::V4(v) => v.octets(),
        _ => bail!("expected IPv4, got IPv6"),
    };

    let total_len = (payload.len() + 20 + 8) as u16;
    let mut data = vec![
        0x45,                // version=4, IHL=5
        0x00,                // ToS
        (total_len >> 8) as u8, (total_len & 0xff) as u8,
        0x00, 0x00,          // identification
        0x40, 0x00,          // DF flag
        64,                  // TTL
        hdr.protocol,
        0x00, 0x00,          // checksum placeholder
    ];
    data.extend_from_slice(&dst_ip);
    data.extend_from_slice(&src_ip);

    // Compute IPv4 header checksum
    let ip_cksum = ipv4_checksum(&data);
    data[10] = (ip_cksum >> 8) as u8;
    data[11] = (ip_cksum & 0xff) as u8;
    buf.extend_from_slice(&data);

    buf.extend_transport_header(rev, payload.len(), hdr.protocol);
    buf.extend_from_slice(payload);

    // Compute UDP checksum
    let udp_cksum = tcp_checksum(&hdr.src, &hdr.dst, 17, &buf[20..]);
    buf[20 + 6] = (udp_cksum >> 8) as u8; // UDP checksum at offset 6 within UDP header
    buf[20 + 7] = (udp_cksum & 0xff) as u8;

    Ok(())
}

fn build_udp_ipv6(
    buf: &mut Vec<u8>,
    payload: &[u8],
    hdr: &IpHeader,
    rev: &ConnKey,
) -> Result<()> {
    let src_ip_raw = rev.src_ip.to_be_bytes();
    let dst_ip_raw = rev.dst_ip.to_be_bytes();
    let ipv6_payload_len = (8 + payload.len()) as u16;

    buf.extend_from_slice(&[
        0x60, 0x00, 0x00, 0x00,
        (ipv6_payload_len >> 8) as u8, (ipv6_payload_len & 0xff) as u8,
        hdr.protocol,
        64, // hop limit
    ]);
    buf.extend_from_slice(&src_ip_raw);
    buf.extend_from_slice(&dst_ip_raw);
    buf.extend_transport_header(rev, payload.len(), hdr.protocol);
    buf.extend_from_slice(payload);

    // UDP checksum (mandatory for IPv6)
    let udp_cksum = tcp_checksum(&hdr.src, &hdr.dst, 17, &buf[40..]);
    buf[40 + 4] = (udp_cksum >> 8) as u8; // UDP checksum at offset 4 within UDP header
    buf[40 + 5] = (udp_cksum & 0xff) as u8;

    Ok(())
}

/// Write UDP transport header with swapped ports.
trait TransportHeaderExt {
    fn extend_transport_header(&mut self, rev: &ConnKey, payload_len: usize, protocol: u8);
}

impl TransportHeaderExt for Vec<u8> {
    fn extend_transport_header(&mut self, rev: &ConnKey, payload_len: usize, protocol: u8) {
        let sport = rev.sport.to_be_bytes();
        let dport = rev.dport.to_be_bytes();
        match protocol {
            17 => { // UDP
                let udp_len = (8 + payload_len) as u16;
                self.extend_from_slice(&[
                    sport[0], sport[1], dport[0], dport[1],
                    (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
                    0x00, 0x00, // checksum
                ]);
            }
            _ => unreachable!(),
        }
    }
}

/// Write a TCP header with proper flags, seq/ack numbers and swapped ports.
fn extend_tcp_response_header(
    buf: &mut Vec<u8>,
    rev: &ConnKey,
    flags: u8,
    seq: u32,
    ack: u32,
) {
    let sport = rev.sport.to_be_bytes();
    let dport = rev.dport.to_be_bytes();
    buf.extend_from_slice(&sport);
    buf.extend_from_slice(&dport);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&ack.to_be_bytes());
    buf.extend_from_slice(&[0x50, flags]); // data offset=5 (20 bytes), flags
    buf.extend_from_slice(&[0xff, 0xff]);   // window
    buf.extend_from_slice(&[0x00, 0x00]);   // checksum (0 = kernel computes)
    buf.extend_from_slice(&[0x00, 0x00]);   // urgent
}

/// Write a packet to the TUN interface via spawn_blocking.
/// Unlike the old approach (File::open per packet), this reuses the existing fd
/// via try_clone + spawn_blocking — no syscall to open /dev/net/tun each time.
async fn write_to_tun(tun_fd: &OwnedFd, packet: &[u8]) {
    if packet.is_empty() {
        return;
    }
    let owned = match tun_fd.try_clone() {
        Ok(fd) => fd,
        Err(e) => {
            tracing::warn!("Failed to clone TUN fd: {e}");
            return;
        }
    };
    let pkt = packet.to_vec(); // Copy so spawn_blocking owns the data
    if let Err(e) = tokio::task::spawn_blocking(move || {
        let mut file = unsafe { std::fs::File::from_raw_fd(owned.as_raw_fd()) };
        std::mem::forget(owned);
        file.write_all(&pkt)
    })
    .await
    {
        tracing::warn!("TUN write task panicked: {e}");
    }
}

/// Resolve the shadowsocks server UDP address to a SocketAddr.
fn resolve_server_addr(svr_cfg: &ServerConfig) -> SocketAddr {
    match svr_cfg.udp_external_addr() {
        shadowsocks::config::ServerAddr::SocketAddr(sa) => *sa,
        shadowsocks::config::ServerAddr::DomainName(_domain, port) => {
            // Default to localhost — DNS resolution happens inside ProxySocket::connect
            SocketAddr::new("127.0.0.1".parse().unwrap(), *port)
        }
    }
}

// ── Main tunnel loop ───────────────────────────────────────────

/// Run the TUN-to-shadowsocks proxy.
#[allow(unreachable_code)]
pub async fn run_tun_tproxy(
    tun_fd: OwnedFd,
    _config: Config,
    ctx: SharedContext,
    svr_cfg: ServerConfig,
) -> Result<()> {
    // Clone the fd once for write_to_tun (pass to async tasks).
    let tun_fd_for_writer = tun_fd.try_clone()?;

    // TCP connections: reversed key → TCP state
    let mut tcp_connections: HashMap<ConnKey, TcpConn> = HashMap::new();

    // UDP connections: reversed key → metadata needed to build response packets
    // Uses Arc<Mutex> so the reader task can look up connections by dst address
    let udp_connections: Arc<std::sync::Mutex<HashMap<ConnKey, UdpConnMeta>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // UDP relay socket (shared across all UDP connections)
    let server_udp_addr = resolve_server_addr(&svr_cfg);

    let udp_socket = match timeout(
        Duration::from_secs(10),
        ProxySocket::connect(ctx.clone(), &svr_cfg),
    )
    .await
    {
        Ok(Ok(socket)) => {
            tracing::info!("UDP relay socket connected");
            socket
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to connect UDP relay socket: {e}, retrying once");
            ProxySocket::connect(ctx.clone(), &svr_cfg).await?
        }
        Err(_) => {
            tracing::warn!("UDP relay socket connection timed out, retrying once");
            ProxySocket::connect(ctx.clone(), &svr_cfg).await?
        }
    };
    let udp_socket = Arc::new(udp_socket);

    // Channel for UDP responses from the reader task
    let (_resp_tx, mut resp_rx) = mpsc::channel::<(Vec<u8>, IpHeader, ConnKey)>(256);

    // Spawn UDP response reader task
    let _udp_reader = {
        let us = udp_socket.clone();
        let udp_conns = udp_connections.clone();
        let tun_clone = tun_fd_for_writer.try_clone()?;
        tokio::spawn(async move {
            udp_response_reader(us, udp_conns, tun_clone).await
        })
    };

    let mut read_buf = [0u8; 65536];

    loop {
        let owned = tun_fd.try_clone()?;
        let n = tokio::task::spawn_blocking(move || {
            let mut file = unsafe { std::fs::File::from_raw_fd(owned.as_raw_fd()) };
            std::mem::forget(owned);
            file.read(&mut read_buf)
        })
        .await
        .unwrap_or(Ok(0))?;

        // Drain UDP response channel before processing TUN packets
        while let Ok((payload, hdr, rev_key)) = resp_rx.try_recv() {
            if let Ok(pkt) = build_response_packet(&payload, &hdr, &rev_key) {
                write_to_tun(&tun_fd, &pkt).await;
            }
        }

        let packet = &read_buf[..n];

        let hdr = match parse_ip_packet(packet) {
            Some(h) => h,
            None => continue,
        };

        let transport_start = hdr.header_len as usize;
        let payload = &packet[transport_start..];
        let rev_key = ConnKey::from_ip(&hdr, hdr.src_port, hdr.dst_port).reversed();

        match hdr.protocol {
            6 => handle_tcp_packet(
                &mut tcp_connections,
                &tun_fd,
                &hdr,
                payload,
                &rev_key,
                &ctx,
                &svr_cfg,
            )
            .await,
            17 => handle_udp_packet(
                &udp_connections,
                &mut tcp_connections,
                &hdr,
                payload,
                &rev_key,
                &udp_socket,
                server_udp_addr,
                &svr_cfg,
            )
            .await,
            _ => continue,
        }
    }

    Ok(())
}

async fn handle_tcp_packet(
    tcp_connections: &mut HashMap<ConnKey, TcpConn>,
    tun_fd: &OwnedFd,
    hdr: &IpHeader,
    payload: &[u8],
    rev_key: &ConnKey,
    ctx: &SharedContext,
    svr_cfg: &ServerConfig,
) {
    match tcp_connections.get_mut(rev_key) {
        Some(conn) => {
            conn.last_active = std::time::Instant::now();

            // Update client_seq if this packet has data
            if !payload.is_empty() {
                conn.client_seq = hdr.tcp_seq + payload.len() as u32;
                if let Err(e) = conn.write_half.write_all(payload).await {
                    tracing::warn!("TCP stream write failed: {e}, removing connection");
                    tcp_connections.remove(rev_key);
                }
            }
        }
        None => {
            let target = match (hdr.version, &hdr.dst, hdr.dst_port) {
                (4, IpAddr::V4(d), p) => Address::SocketAddress(SocketAddr::from((*d, p))),
                (6, IpAddr::V6(d), p) => Address::SocketAddress(SocketAddr::from((*d, p))),
                _ => return,
            };

            // Evict oldest if at capacity
            if tcp_connections.len() >= MAX_CONNECTIONS {
                if let Some(oldest) = tcp_connections
                    .iter()
                    .min_by_key(|(_, c)| c.last_active)
                    .map(|(k, _)| *k)
                {
                    tcp_connections.remove(&oldest);
                    tracing::debug!("Evicted oldest TCP connection (limit: {MAX_CONNECTIONS})");
                }
            }

            let payload = payload.to_vec();
            match timeout(
                Duration::from_secs(10),
                ProxyClientStream::connect(ctx.clone(), svr_cfg, target.clone()),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    let (read_half, mut write_half) = split(stream);
                    tracing::debug!(
                        "New TCP connection: {}:{} → {}",
                        hdr.dst,
                        hdr.dst_port,
                        svr_cfg.addr(),
                    );

                    if !payload.is_empty() {
                        if let Err(e) = write_half.write_all(&payload).await {
                            tracing::warn!("Initial TCP write failed: {e}");
                            return;
                        }
                    }

                    // Spawn per-connection reader: continuously drain SS stream → TUN
                    let tun_clone = tun_fd.try_clone().ok();
                    let client_seq = hdr.tcp_seq;
                    let server_isn = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    if let Some(tun_fd) = tun_clone {
                        let key = *rev_key;
                        tokio::spawn(tcp_reader_task(
                            read_half,
                            tun_fd,
                            *hdr,
                            key,
                            client_seq,
                            server_isn,
                        ));
                    }

                    tcp_connections.insert(
                        *rev_key,
                        TcpConn {
                            write_half,
                            last_active: std::time::Instant::now(),
                            client_seq,
                        },
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to create TCP connection to {}: {e}", target);
                }
                Err(_) => {
                    tracing::warn!("TCP connection to {} timed out", target);
                }
            }
        }
    }
}

/// Per-connection reader: continuously read from SS stream and write to TUN.
/// Runs until the stream closes or errors.
async fn tcp_reader_task(
    mut stream: tokio::io::ReadHalf<ProxyClientStream<SsTcpStream>>,
    tun_fd: OwnedFd,
    orig_hdr: IpHeader, // Original client packet for src/dst
    rev_key: ConnKey,
    client_seq: u32,    // Client's current seq (for ACK in response)
    mut server_seq: u32, // Server's current seq (incremented per response)
) {
    let mut resp_buf = [0u8; 65536];
    loop {
        match stream.read(&mut resp_buf).await {
            Ok(0) => {
                // Stream closed (EOF)
                tracing::debug!("TCP stream EOF for {:?}, removing connection", rev_key);
                return;
            }
            Ok(n) => {
                let resp_data = &resp_buf[..n];
                let pkt = match build_tcp_response_packet(
                    resp_data,
                    &orig_hdr,
                    &rev_key,
                    server_seq,
                    client_seq,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("Failed to build response packet: {e}");
                        return;
                    }
                };
                write_to_tun(&tun_fd, &pkt).await;
                server_seq += n as u32;
            }
            Err(e) => {
                tracing::warn!("TCP stream read error for {:?}: {e}", rev_key);
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_packet(
    udp_connections: &Arc<std::sync::Mutex<HashMap<ConnKey, UdpConnMeta>>>,
    tcp_connections: &mut HashMap<ConnKey, TcpConn>,
    hdr: &IpHeader,
    payload: &[u8],
    rev_key: &ConnKey,
    udp_socket: &Arc<ProxySocket<shadowsocks::net::UdpSocket>>,
    server_udp_addr: SocketAddr,
    svr_cfg: &ServerConfig,
) {
    // Track this UDP flow
    {
        let mut map = udp_connections.lock().unwrap();
        map.insert(*rev_key, UdpConnMeta {
            hdr: *hdr,
            rev_key: *rev_key,
        });
    }

    let target = match (hdr.version, &hdr.dst, hdr.dst_port) {
        (4, IpAddr::V4(d), p) => Address::SocketAddress(SocketAddr::from((*d, p))),
        (6, IpAddr::V6(d), p) => Address::SocketAddress(SocketAddr::from((*d, p))),
        _ => return,
    };

    if payload.is_empty() {
        return;
    }

    let us = udp_socket.clone();
    let addr = target.clone();
    let data = payload.to_vec();

    // Evict oldest TCP connection if at capacity (UDP also contributes)
    let total_conns = tcp_connections.len() + udp_connections.lock().unwrap().len();
    if total_conns >= MAX_CONNECTIONS && !tcp_connections.is_empty() {
        if let Some(oldest) = tcp_connections
            .iter()
            .min_by_key(|(_, c)| c.last_active)
            .map(|(k, _)| *k)
        {
            tcp_connections.remove(&oldest);
            tracing::debug!("Evicted oldest connection (limit: {MAX_CONNECTIONS})");
        }
    }

    match timeout(
        Duration::from_secs(10),
        us.send_to(server_udp_addr, &addr, &data),
    )
    .await
    {
        Ok(Ok(_)) => {
            tracing::debug!(
                "UDP packet: {}:{} → {}:{} via {}",
                hdr.src,
                hdr.src_port,
                hdr.dst,
                hdr.dst_port,
                svr_cfg.addr(),
            );
        }
        Ok(Err(e)) => {
            tracing::warn!("UDP send to {} failed: {e}", addr);
        }
        Err(_) => {
            tracing::warn!("UDP send to {} timed out", addr);
        }
    }
}

/// Background task: continuously read UDP responses from the shadowsocks server
/// and write them directly to the TUN interface.
async fn udp_response_reader(
    udp_socket: Arc<ProxySocket<shadowsocks::net::UdpSocket>>,
    udp_connections: Arc<std::sync::Mutex<HashMap<ConnKey, UdpConnMeta>>>,
    tun_fd: OwnedFd,
) {
    let mut buf = [0u8; 65536];
    loop {
        match timeout(Duration::from_secs(5), udp_socket.recv(&mut buf)).await {
            Ok(Ok((_payload_len, addr, _total_len))) => {
                let (ip, port) = match &addr {
                    Address::SocketAddress(sa) => (sa.ip(), sa.port()),
                    Address::DomainNameAddress(domain, port) => {
                        tracing::debug!("UDP response contains domain address: {domain}:{port}, skipping");
                        continue;
                    }
                };

                // Find matching UDP connection by destination address
                let conn_info = {
                    let map = udp_connections.lock().unwrap();
                    map.iter()
                        .find(|(_, meta)| {
                            meta.hdr.dst == ip && meta.hdr.dst_port == port
                        })
                        .map(|(_, meta)| meta.clone())
                };

                if let Some(meta) = conn_info {
                    if let Ok(pkt) = build_response_packet(&buf[.._payload_len], &meta.hdr, &meta.rev_key) {
                        write_to_tun(&tun_fd, &pkt).await;
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("UDP response read failed: {e}");
                continue;
            }
            Err(_) => continue, // timeout, keep reading
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv4 packet parsing ──

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        // src: 10.0.0.1
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        // dst: 1.2.3.4
        pkt[16..20].copy_from_slice(&[1, 2, 3, 4]);
        // src port: 12345
        pkt[20..22].copy_from_slice(&[0x30, 0x39]);
        // dst port: 443
        pkt[22..24].copy_from_slice(&[0x01, 0xbb]);

        let hdr = parse_ip_packet(&pkt).expect("parse IPv4 TCP");
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.protocol, 6);
        assert_eq!(hdr.header_len, 20);
        assert_eq!(hdr.src_port, 12345);
        assert_eq!(hdr.dst_port, 443);
    }

    #[test]
    fn test_parse_ipv4_udp_packet() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        // src: 192.168.1.100
        pkt[12..16].copy_from_slice(&[192, 168, 1, 100]);
        // dst: 8.8.8.8
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // src port: 50000
        pkt[20..22].copy_from_slice(&[0xc3, 0x50]);
        // dst port: 53
        pkt[22..24].copy_from_slice(&[0x00, 0x35]);

        let hdr = parse_ip_packet(&pkt).expect("parse IPv4 UDP");
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.protocol, 17);
        assert_eq!(hdr.src_port, 50000);
        assert_eq!(hdr.dst_port, 53);
    }

    #[test]
    fn test_parse_ipv6_tcp_packet() {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60; // version=6
        // src: 2001:df8::1
        pkt[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xf8, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        // dst: 2001:df8::2
        pkt[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xf8, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ]);
        pkt[4] = 6; // Next header = TCP
        // src port: 54321
        pkt[40..42].copy_from_slice(&[0xd4, 0x31]);
        // dst port: 443
        pkt[42..44].copy_from_slice(&[0x01, 0xbb]);

        let hdr = parse_ip_packet(&pkt).expect("parse IPv6 TCP");
        assert_eq!(hdr.version, 6);
        assert_eq!(hdr.protocol, 6);
        assert!(matches!(hdr.src, IpAddr::V6(_)));
        assert!(matches!(hdr.dst, IpAddr::V6(_)));
        assert_eq!(hdr.src_port, 54321);
        assert_eq!(hdr.dst_port, 443);
    }

    #[test]
    fn test_parse_ipv6_udp_packet() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        // src: fe80::1
        pkt[8..24].copy_from_slice(&[
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        // dst: 2001:df8::1
        pkt[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xf8, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        pkt[4] = 17; // Next header = UDP
        // src port: 50000
        pkt[40..42].copy_from_slice(&[0xc3, 0x50]);
        // dst port: 1234
        pkt[42..44].copy_from_slice(&[0x04, 0xd2]);

        let hdr = parse_ip_packet(&pkt).expect("parse IPv6 UDP");
        assert_eq!(hdr.version, 6);
        assert_eq!(hdr.protocol, 17);
        assert_eq!(hdr.src_port, 50000);
        assert_eq!(hdr.dst_port, 1234);
    }

    #[test]
    fn test_parse_too_short_packet() {
        let pkt = vec![0u8; 39];
        assert!(parse_ip_packet(&pkt).is_none());
    }

    #[test]
    fn test_parse_invalid_version() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x35; // version 3
        assert!(parse_ip_packet(&pkt).is_none());
    }

    #[test]
    fn test_parse_null_protocol_ignored() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 1; // ICMP
        assert!(parse_ip_packet(&pkt).is_none());
    }

    // ── IPv6 payload length ──

    #[test]
    fn test_ipv6_response_payload_length_100() {
        let original = IpHeader {
            version: 6,
            src: IpAddr::V6("fe80::1".parse().unwrap()),
            dst: IpAddr::V6("2001:db8::1".parse().unwrap()),
            protocol: 17,
            header_len: 40,
            src_port: 54321,
            dst_port: 443,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let rev = ConnKey::from_ip(&original, original.src_port, original.dst_port).reversed();
        let payload = vec![0xab; 100];

        let pkt = build_response_packet(&payload, &original, &rev).expect("build IPv6 UDP");

        // IPv6 payload len = UDP header(8) + payload(100) = 108
        let ipv6_payload_len = u16::from_be_bytes([pkt[4], pkt[5]]);
        assert_eq!(ipv6_payload_len, 108);
    }

    #[test]
    fn test_ipv6_udp_response_payload_length() {
        let original = IpHeader {
            version: 6,
            src: IpAddr::V6("fe80::1".parse().unwrap()),
            dst: IpAddr::V6("2001:db8::1".parse().unwrap()),
            protocol: 17,
            header_len: 40,
            src_port: 50000,
            dst_port: 53,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let rev = ConnKey::from_ip(&original, original.src_port, original.dst_port).reversed();
        let payload = vec![0xde; 50];

        let pkt = build_response_packet(&payload, &original, &rev).expect("build IPv6 UDP");

        // IPv6 payload len = UDP header(8) + payload(50) = 58
        let ipv6_payload_len = u16::from_be_bytes([pkt[4], pkt[5]]);
        assert_eq!(ipv6_payload_len, 58);
    }

    #[test]
    fn test_ipv4_response_total_length_200() {
        let original = IpHeader {
            version: 4,
            src: IpAddr::V4("10.0.0.1".parse().unwrap()),
            dst: IpAddr::V4("1.2.3.4".parse().unwrap()),
            protocol: 17,
            header_len: 20,
            src_port: 12345,
            dst_port: 443,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let rev = ConnKey::from_ip(&original, original.src_port, original.dst_port).reversed();
        let payload = vec![0x42; 200];

        let pkt = build_response_packet(&payload, &original, &rev).expect("build IPv4 UDP");

        // Total IP len = IP(20) + UDP(8) + payload(200) = 228
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(total_len, 228);
    }

    #[test]
    fn test_ipv4_udp_response_total_length() {
        let original = IpHeader {
            version: 4,
            src: IpAddr::V4("10.0.0.1".parse().unwrap()),
            dst: IpAddr::V4("1.2.3.4".parse().unwrap()),
            protocol: 17,
            header_len: 20,
            src_port: 50000,
            dst_port: 53,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let rev = ConnKey::from_ip(&original, original.src_port, original.dst_port).reversed();
        let payload = vec![0x42; 100];

        let pkt = build_response_packet(&payload, &original, &rev).expect("build IPv4 UDP");

        // Total IP len = IP(20) + UDP(8) + payload(100) = 128
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(total_len, 128);
    }

    // ── Connection key ──

    #[test]
    fn test_conn_key_reversed() {
        let hdr = IpHeader {
            version: 4,
            src: IpAddr::V4("10.0.0.1".parse().unwrap()),
            dst: IpAddr::V4("1.2.3.4".parse().unwrap()),
            protocol: 6,
            header_len: 20,
            src_port: 1234,
            dst_port: 5678,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let key = ConnKey::from_ip(&hdr, hdr.src_port, hdr.dst_port);
        let rev = key.reversed();

        assert_eq!(rev.src_ip, key.dst_ip);
        assert_eq!(rev.dst_ip, key.src_ip);
        assert_eq!(rev.sport, key.dport);
        assert_eq!(rev.dport, key.sport);
        assert_eq!(rev.proto, key.proto);
        assert_eq!(rev.version, key.version);
        assert_eq!(rev.reversed(), key);
    }

    // ── Response packet address/port swap ──

    #[test]
    fn test_ipv4_response_address_swap() {
        let original = IpHeader {
            version: 4,
            src: IpAddr::V4("10.0.0.1".parse().unwrap()),
            dst: IpAddr::V4("1.2.3.4".parse().unwrap()),
            protocol: 17,
            header_len: 20,
            src_port: 1234,
            dst_port: 5678,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let rev = ConnKey::from_ip(&original, original.src_port, original.dst_port).reversed();
        let payload = vec![0x01, 0x02];

        let pkt = build_response_packet(&payload, &original, &rev).expect("build response");

        // Response src = original dst = 1.2.3.4 (swapped)
        assert_eq!(pkt[12..16], [1, 2, 3, 4]);
        // Response dst = original src = 10.0.0.1 (swapped)
        assert_eq!(pkt[16..20], [10, 0, 0, 1]);
        // Ports swapped: src=5678 (0x162e), dst=1234 (0x04d2)
        assert_eq!(&pkt[20..24], &[0x16, 0x2e, 0x04, 0xd2]);
    }

    #[test]
    fn test_ipv6_response_address_swap() {
        let original = IpHeader {
            version: 6,
            src: IpAddr::V6("2001:db8::1".parse().unwrap()),
            dst: IpAddr::V6("2001:db8::2".parse().unwrap()),
            protocol: 17,
            header_len: 40,
            src_port: 5000,
            dst_port: 53,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        };
        let rev = ConnKey::from_ip(&original, original.src_port, original.dst_port).reversed();
        let payload = vec![0xaa];

        let pkt = build_response_packet(&payload, &original, &rev).expect("build response");

        // Response src = original dst = 2001:db8::2 (swapped)
        assert_eq!(&pkt[8..24], &[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ]);
        // Response dst = original src = 2001:db8::1 (swapped)
        assert_eq!(&pkt[24..40], &[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
    }

    // ── Edge cases ──

    #[test]
    fn test_parse_ip_options_ignored() {
        // IHL > 5 means IP options, skip parsing (ihl >= 20 but > 40 bytes needed for TCP)
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x46; // IHL=6 (24 bytes IP header) — still less than 40
        // protocol is TCP but we need at least 40 bytes total with TCP header
        // With IHL=6, transport_start=24, TCP header at 24..44 but buf only has 40 bytes
        assert!(parse_ip_packet(&pkt).is_none());
    }
}
