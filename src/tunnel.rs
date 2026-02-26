use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::icmp;
use crate::proxy::SsProxy;

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const TCP_RELAY_BUF_SIZE: usize = 32 * 1024;
const METRICS_LOG_PERIOD: Duration = Duration::from_secs(30);

static ACTIVE_TCP_RELAYS: AtomicI64 = AtomicI64::new(0);
static ACTIVE_UDP_RELAYS: AtomicI64 = AtomicI64::new(0);
static TCP_RELAY_ERRORS: AtomicU64 = AtomicU64::new(0);
static TCP_RELAY_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static UDP_RELAY_ERRORS: AtomicU64 = AtomicU64::new(0);
static ICMP_REPLIES: AtomicU64 = AtomicU64::new(0);

/// Tunnel connects a TUN device to a Shadowsocks proxy using netstack-smoltcp.
pub struct Tunnel {
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _tun_fd: Arc<OwnedFd>,
}

impl Tunnel {
    pub fn new(tun_fd: OwnedFd, mtu: u16, proxy: SsProxy) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let proxy = Arc::new(proxy);
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // Build the netstack-smoltcp stack
        let (stack, runner, udp_socket, tcp_listener) =
            netstack_smoltcp::StackBuilder::default()
                .stack_buffer_size(512)
                .tcp_buffer_size(262144)
                .enable_udp(true)
                .enable_tcp(true)
                .enable_icmp(true)
                .build()
                .context("build netstack-smoltcp stack")?;

        // Runner returns Result — wrap it to match JoinHandle<()>
        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                if let Err(e) = runner.await {
                    tracing::error!("netstack runner error: {e}");
                }
            }));
        }

        let tcp_listener = tcp_listener.expect("TCP listener should exist when TCP enabled");
        let udp_socket = udp_socket.expect("UDP socket should exist when UDP enabled");

        // Stack implements Stream + Sink; split via futures
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
                let fd = tun_fd_read.as_raw_fd();
                let mut buf = vec![0u8; mtu as usize + 4];

                loop {
                    if *shutdown_rx.borrow() {
                        return;
                    }

                    // Poll for data with 100ms timeout using libc directly
                    let mut pfd = nix::libc::pollfd {
                        fd,
                        events: nix::libc::POLLIN,
                        revents: 0,
                    };
                    let poll_ret = unsafe { nix::libc::poll(&mut pfd, 1, 100) };

                    if poll_ret <= 0 {
                        continue; // timeout or EINTR
                    }

                    let n = unsafe {
                        nix::libc::read(fd, buf.as_mut_ptr() as *mut nix::libc::c_void, buf.len())
                    };
                    if n <= 0 {
                        continue;
                    }
                    let n = n as usize;
                    let pkt_data = &buf[..n];

                    // Intercept ICMP echo requests and reply instantly
                    if let Some(reply) = icmp::handle_icmp_echo(pkt_data) {
                        let icmp_fd = tun_fd_icmp.as_raw_fd();
                        unsafe {
                            nix::libc::write(
                                icmp_fd,
                                reply.as_ptr() as *const nix::libc::c_void,
                                reply.len(),
                            );
                        }
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
                }
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
                                Some(Ok(frame)) => {
                                    let data: &[u8] = frame.as_ref();
                                    unsafe {
                                        nix::libc::write(
                                            fd,
                                            data.as_ptr() as *const nix::libc::c_void,
                                            data.len(),
                                        );
                                    }
                                }
                                Some(Err(e)) => {
                                    tracing::debug!("Stack stream error: {e}");
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
        {
            let proxy = proxy.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let (mut udp_read, udp_write) = udp_socket.split();
            let udp_write = Arc::new(Mutex::new(udp_write));

            // Sessions map: (src, dst) → channel sender for outgoing packets
            let sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), tokio::sync::mpsc::Sender<Vec<u8>>>>> =
                Arc::new(Mutex::new(HashMap::new()));

            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        msg = udp_read.next() => {
                            let Some((payload, local_addr, remote_addr)) = msg else {
                                return;
                            };

                            let dst = local_addr;  // original destination
                            let src = remote_addr;  // source client
                            let key = (src, dst);

                            let proxy = proxy.clone();
                            let sessions = sessions.clone();
                            let udp_write = udp_write.clone();

                            tokio::spawn(async move {
                                // Check if session exists
                                let existing_tx = {
                                    let map = sessions.lock().await;
                                    map.get(&key).cloned()
                                };

                                if let Some(tx) = existing_tx {
                                    // Send to existing session
                                    let _ = tx.send(payload).await;
                                } else {
                                    // Create new session
                                    ACTIVE_UDP_RELAYS.fetch_add(1, Ordering::Relaxed);

                                    let session = match proxy.new_udp_session(dst).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!("[UDP] dial fail {src} -> {dst}: {e}");
                                            UDP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
                                            ACTIVE_UDP_RELAYS.fetch_sub(1, Ordering::Relaxed);
                                            return;
                                        }
                                    };

                                    tracing::debug!("[UDP] {src} <-> {dst}");

                                    let tx = session.outgoing.clone();
                                    {
                                        let mut map = sessions.lock().await;
                                        map.insert(key, session.outgoing);
                                    }

                                    // Send initial packet
                                    let _ = tx.send(payload).await;

                                    // Spawn reverse relay: SS → local
                                    let sessions_cleanup = sessions.clone();
                                    let udp_write_clone = udp_write.clone();
                                    tokio::spawn(async move {
                                        let mut incoming = session.incoming;
                                        loop {
                                            let recv = tokio::time::timeout(
                                                UDP_SESSION_TIMEOUT,
                                                incoming.recv(),
                                            ).await;

                                            match recv {
                                                Ok(Some(data)) => {
                                                    let msg = (data, src, dst);
                                                    let mut writer = udp_write_clone.lock().await;
                                                    if let Err(e) = writer.send(msg).await {
                                                        tracing::debug!("[UDP] write back error: {e}");
                                                        break;
                                                    }
                                                }
                                                Ok(None) => break, // channel closed
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

    pub async fn close(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
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
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE_TCP_RELAYS.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _guard = Guard;

    let start = Instant::now();
    let target = local_addr;

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
        if e.kind() == io::ErrorKind::TimedOut {
            TCP_RELAY_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("[TCP] {remote_addr} <-> {target}: timeout after {elapsed:?}");
        } else {
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("[TCP] {remote_addr} <-> {target}: error after {elapsed:?}: {e}");
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
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")),
        };

        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}
