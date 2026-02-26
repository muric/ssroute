use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use shadowsocks::relay::Address;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::icmp;
use crate::proxy::SsProxy;

/// Helper: borrow a raw fd as BorrowedFd (caller must ensure fd is valid).
unsafe fn borrow_fd(fd: i32) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const TCP_RELAY_BUF_SIZE: usize = 32 * 1024;
const UDP_RECV_BUF_SIZE: usize = 65536;
const METRICS_LOG_PERIOD: Duration = Duration::from_secs(30);

// Global telemetry counters
static ACTIVE_TCP_RELAYS: AtomicI64 = AtomicI64::new(0);
static ACTIVE_UDP_RELAYS: AtomicI64 = AtomicI64::new(0);
static TCP_RELAY_ERRORS: AtomicU64 = AtomicU64::new(0);
static TCP_RELAY_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static UDP_RELAY_ERRORS: AtomicU64 = AtomicU64::new(0);
static ICMP_REPLIES: AtomicU64 = AtomicU64::new(0);
static TUN_PACKETS_DISPATCHED: AtomicU64 = AtomicU64::new(0);

type ProxySocketArc = Arc<shadowsocks::relay::udprelay::proxy_socket::ProxySocket>;

/// Tunnel connects a TUN device to a Shadowsocks proxy using netstack-smoltcp.
pub struct Tunnel {
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _tun_fd: Arc<OwnedFd>,
}

impl Tunnel {
    /// Create and start a new tunnel.
    pub fn new(tun_fd: OwnedFd, mtu: u16, proxy: SsProxy) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let proxy = Arc::new(proxy);
        let mut tasks = Vec::new();

        // Build the netstack-smoltcp stack
        let (stack, runner, udp_socket, tcp_listener) =
            netstack_smoltcp::StackBuilder::default()
                .stack_buffer_size(512)
                .tcp_buffer_size(262144) // 256KB
                .enable_udp(true)
                .enable_tcp(true)
                .enable_icmp(true)
                .build()
                .context("build netstack-smoltcp stack")?;

        if let Some(runner) = runner {
            tasks.push(tokio::spawn(runner));
        }

        let tcp_listener = tcp_listener.expect("TCP listener should exist when TCP enabled");
        let udp_socket = udp_socket.expect("UDP socket should exist when UDP enabled");

        // Stack implements both Stream and Sink; split via futures
        let (stack_sink, stack_stream) = stack.split();
        let stack_sink = Arc::new(Mutex::new(stack_sink));

        let tun_fd = Arc::new(tun_fd);
        let tun_fd_read = tun_fd.clone();
        let tun_fd_write = tun_fd.clone();
        let tun_fd_icmp = tun_fd.clone();

        // ---- Task: TUN → Stack (with ICMP interception) ----
        {
            let shutdown_rx = shutdown_rx.clone();
            let stack_sink = stack_sink.clone();

            tasks.push(tokio::spawn(async move {
                tun_to_stack(
                    tun_fd_read,
                    tun_fd_icmp,
                    stack_sink,
                    shutdown_rx,
                    mtu,
                )
                .await;
            }));
        }

        // ---- Task: Stack → TUN ----
        {
            let mut shutdown_rx = shutdown_rx.clone();
            let mut stack_stream = stack_stream;

            tasks.push(tokio::spawn(async move {
                let fd = tun_fd_write.as_raw_fd();
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        pkt = stack_stream.next() => {
                            match pkt {
                                Some(frame) => {
                                    let data: &[u8] = frame.as_ref();
                                    let _ = nix::unistd::write(
                                        unsafe { borrow_fd(fd) },
                                        data,
                                    );
                                }
                                None => return,
                            }
                        }
                    }
                }
            }));
        }

        // ---- Task: TCP handler ----
        {
            let proxy = proxy.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let mut tcp_listener = tcp_listener;

            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        conn = tcp_listener.next() => {
                            match conn {
                                Some((tcp_stream, local_addr, remote_addr)) => {
                                    let proxy = proxy.clone();
                                    tokio::spawn(async move {
                                        handle_tcp(tcp_stream, local_addr, remote_addr, proxy).await;
                                    });
                                }
                                None => return,
                            }
                        }
                    }
                }
            }));
        }

        // ---- Task: UDP handler ----
        // UdpSocket::split() returns types from a private module,
        // so we handle everything inline here.
        {
            let proxy = proxy.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let (mut udp_read, udp_write) = udp_socket.split();
            let udp_write = Arc::new(Mutex::new(udp_write));

            // Session map: (src, dst) → ProxySocket
            let sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), ProxySocketArc>>> =
                Arc::new(Mutex::new(HashMap::new()));

            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        msg = udp_read.next() => {
                            let Some((payload, local_addr, remote_addr)) = msg else {
                                return;
                            };

                            let dst = local_addr;
                            let src = remote_addr;
                            let key = (src, dst);

                            let proxy = proxy.clone();
                            let sessions = sessions.clone();
                            let udp_write = udp_write.clone();

                            tokio::spawn(async move {
                                let needs_new = {
                                    let map = sessions.lock().await;
                                    !map.contains_key(&key)
                                };

                                if needs_new {
                                    ACTIVE_UDP_RELAYS.fetch_add(1, Ordering::Relaxed);

                                    let proxy_socket = match proxy.dial_udp().await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!("[UDP] dial fail {src} -> {dst}: {e}");
                                            UDP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
                                            ACTIVE_UDP_RELAYS.fetch_sub(1, Ordering::Relaxed);
                                            return;
                                        }
                                    };

                                    tracing::debug!("[UDP] {src} <-> {dst}");

                                    let proxy_socket: ProxySocketArc = Arc::new(proxy_socket);
                                    {
                                        let mut map = sessions.lock().await;
                                        map.insert(key, proxy_socket.clone());
                                    }

                                    // Spawn reverse relay: SS → local
                                    let sessions_cleanup = sessions.clone();
                                    let udp_write_clone = udp_write.clone();
                                    let ps = proxy_socket.clone();
                                    tokio::spawn(async move {
                                        let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
                                        loop {
                                            let recv = tokio::time::timeout(
                                                UDP_SESSION_TIMEOUT,
                                                ps.recv(&mut buf),
                                            ).await;

                                            match recv {
                                                Ok(Ok((n, _addr, _))) => {
                                                    let msg = (buf[..n].to_vec(), src, dst);
                                                    let mut writer = udp_write_clone.lock().await;
                                                    if let Err(e) = writer.send(msg).await {
                                                        tracing::debug!("[UDP] write back error: {e}");
                                                        break;
                                                    }
                                                }
                                                Ok(Err(e)) => {
                                                    tracing::debug!("[UDP] recv error: {e}");
                                                    UDP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
                                                    break;
                                                }
                                                Err(_) => {
                                                    tracing::debug!("[UDP] session timeout {src} <-> {dst}");
                                                    break;
                                                }
                                            }
                                        }
                                        // Cleanup
                                        let mut map = sessions_cleanup.lock().await;
                                        map.remove(&key);
                                        ACTIVE_UDP_RELAYS.fetch_sub(1, Ordering::Relaxed);
                                    });

                                    // Send the initial packet
                                    let target = Address::SocketAddress(dst);
                                    if let Err(e) = proxy_socket.send(&target, &payload).await {
                                        tracing::debug!("[UDP] send error {src} -> {dst}: {e}");
                                    }
                                } else {
                                    // Existing session
                                    let map = sessions.lock().await;
                                    if let Some(ps) = map.get(&key) {
                                        let target = Address::SocketAddress(dst);
                                        if let Err(e) = ps.send(&target, &payload).await {
                                            tracing::debug!("[UDP] send error {src} -> {dst}: {e}");
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }));
        }

        // ---- Task: Telemetry ----
        {
            let mut shutdown_rx = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(METRICS_LOG_PERIOD);
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        _ = interval.tick() => {
                            tracing::info!(
                                "[Stats] TCP: {}, UDP: {} | Errs: TCP:{}, UDP:{} | ICMP: {}",
                                ACTIVE_TCP_RELAYS.load(Ordering::Relaxed),
                                ACTIVE_UDP_RELAYS.load(Ordering::Relaxed),
                                TCP_RELAY_ERRORS.load(Ordering::Relaxed),
                                UDP_RELAY_ERRORS.load(Ordering::Relaxed),
                                ICMP_REPLIES.load(Ordering::Relaxed),
                            );
                        }
                    }
                }
            }));
        }

        Ok(Self {
            shutdown: shutdown_tx,
            tasks,
            _tun_fd: tun_fd,
        })
    }

    /// Shut down the tunnel.
    pub async fn close(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

/// TUN → Stack reader with ICMP interception.
async fn tun_to_stack(
    tun_fd_read: Arc<OwnedFd>,
    tun_fd_icmp: Arc<OwnedFd>,
    stack_sink: Arc<Mutex<futures::stream::SplitSink<netstack_smoltcp::Stack, netstack_smoltcp::AnyIpPktFrame>>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mtu: u16,
) {
    let fd = tun_fd_read.as_raw_fd();
    let mut buf = vec![0u8; mtu as usize + 4];

    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        // Poll for data with 100ms timeout
        let mut poll_fds = [nix::poll::PollFd::new(
            unsafe { borrow_fd(fd) },
            nix::poll::PollFlags::POLLIN,
        )];

        let poll_result = nix::poll::poll(&mut poll_fds, nix::poll::PollTimeout::from(100u16));

        match poll_result {
            Ok(0) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                if *shutdown_rx.borrow() {
                    return;
                }
                tracing::error!("TUN poll error: {e}");
                continue;
            }
            Ok(_) => {}
        }

        let n = match nix::unistd::read(unsafe { borrow_fd(fd) }, &mut buf) {
            Ok(n) if n == 0 => continue,
            Ok(n) => n,
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EWOULDBLOCK) => continue,
            Err(e) => {
                if *shutdown_rx.borrow() {
                    return;
                }
                tracing::error!("TUN read error: {e}");
                continue;
            }
        };

        let pkt_data = &buf[..n];

        // Intercept ICMP echo requests and reply instantly
        if let Some(reply) = icmp::handle_icmp_echo(pkt_data) {
            let icmp_fd = tun_fd_icmp.as_raw_fd();
            let _ = nix::unistd::write(
                unsafe { borrow_fd(icmp_fd) },
                &reply,
            );
            ICMP_REPLIES.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // Inject into the network stack
        let frame: netstack_smoltcp::AnyIpPktFrame = pkt_data.to_vec().into();
        let mut sink = stack_sink.lock().await;
        if let Err(e) = sink.send(frame).await {
            if *shutdown_rx.borrow() {
                return;
            }
            tracing::error!("Stack inject error: {e}");
        }
        TUN_PACKETS_DISPATCHED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Handle a single TCP connection from the netstack.
async fn handle_tcp(
    tcp_stream: netstack_smoltcp::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    proxy: Arc<SsProxy>,
) {
    ACTIVE_TCP_RELAYS.fetch_add(1, Ordering::Relaxed);
    struct TcpRelayGuard;
    impl Drop for TcpRelayGuard {
        fn drop(&mut self) {
            ACTIVE_TCP_RELAYS.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _guard = TcpRelayGuard;

    let start = Instant::now();
    let target = local_addr; // original destination

    tracing::debug!("[TCP] {remote_addr} <-> {target}");

    let remote_stream = match proxy.dial_tcp(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[TCP] dial fail {remote_addr} -> {target}: {e}");
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if let Err(e) = relay_tcp(tcp_stream, remote_stream).await {
        let elapsed = start.elapsed();
        if is_timeout(&e) {
            TCP_RELAY_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("[TCP] {remote_addr} <-> {target}: timeout after {elapsed:?}");
        } else {
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                "[TCP] {remote_addr} <-> {target}: error after {elapsed:?}: {e}"
            );
        }
    }
}

/// Bidirectional TCP relay with idle timeout.
async fn relay_tcp<A, B>(mut a: A, mut b: B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(&mut a);
    let (mut b_read, mut b_write) = tokio::io::split(&mut b);

    let a_to_b = copy_with_timeout(&mut a_read, &mut b_write, TCP_IDLE_TIMEOUT);
    let b_to_a = copy_with_timeout(&mut b_read, &mut a_write, TCP_IDLE_TIMEOUT);

    tokio::select! {
        r = a_to_b => r?,
        r = b_to_a => r?,
    };

    Ok(())
}

async fn copy_with_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    timeout: Duration,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; TCP_RELAY_BUF_SIZE];
    let mut total: u64 = 0;

    loop {
        let n = match tokio::time::timeout(timeout, reader.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(total),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout"));
            }
        };

        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

fn is_timeout(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut
}
