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
use tokio::sync::{mpsc, Mutex};

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

        // Build netstack-smoltcp
        let (stack, runner, udp_socket, tcp_listener) =
            netstack_smoltcp::StackBuilder::default()
                .stack_buffer_size(512)
                .tcp_buffer_size(262144)
                .enable_udp(true)
                .enable_tcp(true)
                .enable_icmp(true)
                .build()
                .context("build netstack-smoltcp stack")?;

        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                if let Err(e) = runner.await {
                    tracing::error!("netstack runner error: {e}");
                }
            }));
        }

        let tcp_listener = tcp_listener.expect("TCP listener should exist");
        let udp_socket = udp_socket.expect("UDP socket should exist");

        // Channels for TUN <-> Stack communication (avoids BiLock from futures::split)
        let (tun_to_stack_tx, tun_to_stack_rx) = mpsc::channel::<Vec<u8>>(512);
        let (stack_to_tun_tx, stack_to_tun_rx) = mpsc::channel::<Vec<u8>>(512);

        let tun_fd = Arc::new(tun_fd);

        // ---- Task: TUN reader (blocking I/O in spawn_blocking) ----
        {
            let tun_fd_read = tun_fd.clone();
            let tun_fd_icmp = tun_fd.clone();
            let shutdown_rx = shutdown_rx.clone();

            tasks.push(tokio::spawn(async move {
                let fd = tun_fd_read.as_raw_fd();
                let icmp_fd = tun_fd_icmp.as_raw_fd();
                let mut buf = vec![0u8; mtu as usize + 4];

                loop {
                    if *shutdown_rx.borrow() {
                        return;
                    }

                    let mut pfd = nix::libc::pollfd {
                        fd,
                        events: nix::libc::POLLIN,
                        revents: 0,
                    };
                    let poll_ret = unsafe { nix::libc::poll(&mut pfd, 1, 100) };
                    if poll_ret <= 0 {
                        continue;
                    }

                    let n = unsafe {
                        nix::libc::read(
                            fd,
                            buf.as_mut_ptr() as *mut nix::libc::c_void,
                            buf.len(),
                        )
                    };
                    if n <= 0 {
                        continue;
                    }
                    let n = n as usize;
                    let pkt = &buf[..n];

                    // ICMP interception
                    if let Some(reply) = icmp::handle_icmp_echo(pkt) {
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

                    if tun_to_stack_tx.send(pkt.to_vec()).await.is_err() {
                        return;
                    }
                }
            }));
        }

        // ---- Task: TUN writer ----
        {
            let tun_fd_write = tun_fd.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let mut stack_to_tun_rx = stack_to_tun_rx;

            tasks.push(tokio::spawn(async move {
                let fd = tun_fd_write.as_raw_fd();
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        pkt = stack_to_tun_rx.recv() => {
                            match pkt {
                                Some(data) => {
                                    unsafe {
                                        nix::libc::write(
                                            fd,
                                            data.as_ptr() as *const nix::libc::c_void,
                                            data.len(),
                                        );
                                    }
                                }
                                None => return,
                            }
                        }
                    }
                }
            }));
        }

        // ---- Task: Stack handler (single task, no split/BiLock) ----
        // Handles both directions: TUN→Stack and Stack→TUN
        {
            let mut shutdown_rx = shutdown_rx.clone();
            let mut tun_to_stack_rx = tun_to_stack_rx;
            let mut stack = stack;

            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,

                        // Inject packet from TUN into the stack
                        pkt = tun_to_stack_rx.recv() => {
                            match pkt {
                                Some(data) => {
                                    let frame: netstack_smoltcp::AnyIpPktFrame = data.into();
                                    if let Err(e) = stack.send(frame).await {
                                        tracing::debug!("Stack send error: {e}");
                                    }
                                }
                                None => return,
                            }
                        }

                        // Extract outgoing packet from the stack to TUN
                        frame = stack.next() => {
                            match frame {
                                Some(Ok(data)) => {
                                    let bytes: Vec<u8> = data.into();
                                    let _ = stack_to_tun_tx.send(bytes).await;
                                }
                                Some(Err(e)) => {
                                    tracing::debug!("Stack recv error: {e}");
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

            let sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>> =
                Arc::new(Mutex::new(HashMap::new()));

            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        msg = udp_read.next() => {
                            let Some((payload, local_addr, remote_addr)) = msg else {
                                return;
                            };

                            // In netstack-smoltcp: local_addr = source (client), remote_addr = destination
                            let src = local_addr;
                            let dst = remote_addr;
                            let key = (src, dst);

                            let proxy = proxy.clone();
                            let sessions = sessions.clone();
                            let udp_write = udp_write.clone();

                            tokio::spawn(async move {
                                let existing_tx = {
                                    let map = sessions.lock().await;
                                    map.get(&key).cloned()
                                };

                                if let Some(tx) = existing_tx {
                                    let _ = tx.send(payload).await;
                                } else {
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

                                    tracing::info!("[UDP] new session {src} <-> {dst}");

                                    let tx = session.outgoing.clone();
                                    {
                                        let mut map = sessions.lock().await;
                                        map.insert(key, session.outgoing);
                                    }

                                    let _ = tx.send(payload).await;

                                    // Reverse relay task
                                    let sessions_cleanup = sessions.clone();
                                    let udp_write_clone = udp_write.clone();
                                    tokio::spawn(async move {
                                        let mut incoming = session.incoming;
                                        loop {
                                            let recv = tokio::time::timeout(
                                                UDP_SESSION_TIMEOUT,
                                                incoming.recv(),
                                            )
                                            .await;

                                            match recv {
                                                Ok(Some(data)) => {
                                                    let msg = (data, src, dst);
                                                    let mut writer = udp_write_clone.lock().await;
                                                    if let Err(e) = writer.send(msg).await {
                                                        tracing::debug!("[UDP] write back error: {e}");
                                                        break;
                                                    }
                                                }
                                                Ok(None) => break,
                                                Err(_) => {
                                                    tracing::debug!("[UDP] timeout {src} <-> {dst}");
                                                    break;
                                                }
                                            }
                                        }
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
    // In netstack-smoltcp: local_addr = source (client), remote_addr = destination (target)
    let src = local_addr;
    let target = remote_addr;

    let remote_stream = match proxy.dial_tcp(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[TCP] dial fail {src} -> {target}: {e}");
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    tracing::info!("[TCP] relay {src} <-> {target}");

    if let Err(e) = relay_tcp(tcp_stream, remote_stream).await {
        let elapsed = start.elapsed();
        if e.kind() == io::ErrorKind::TimedOut {
            TCP_RELAY_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        } else {
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            tracing::info!("[TCP] error {src} <-> {target} after {elapsed:?}: {e}");
        }
    } else {
        let elapsed = start.elapsed();
        tracing::info!("[TCP] done {src} <-> {target} after {elapsed:?}");
    }
}

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
