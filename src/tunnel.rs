use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::io::unix::AsyncFd;
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

/// Async TUN device wrapper — uses epoll via tokio, never blocks worker threads.
struct TunDevice {
    async_fd: AsyncFd<OwnedFd>,
}

impl TunDevice {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self { async_fd: AsyncFd::new(fd)? })
    }

    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe {
                    nix::libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len())
                };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    fn write(&self, data: &[u8]) {
        let fd = self.async_fd.as_raw_fd();
        unsafe { nix::libc::write(fd, data.as_ptr() as *const _, data.len()); }
    }
}

pub struct Tunnel {
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _tun: Arc<TunDevice>,
}

impl Tunnel {
    pub fn new(tun_fd: OwnedFd, mtu: u16, proxy: SsProxy) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let proxy = Arc::new(proxy);
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        let tun = Arc::new(TunDevice::new(tun_fd).context("async TUN device")?);

        let (stack, runner, udp_socket, tcp_listener) =
            netstack_smoltcp::StackBuilder::default()
                .stack_buffer_size(512)
                .tcp_buffer_size(262144)
                .enable_udp(true)
                .enable_tcp(true)
                .enable_icmp(true)
                .build()
                .context("build netstack")?;

        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                if let Err(e) = runner.await {
                    tracing::error!("netstack runner error: {e}");
                }
            }));
        }

        let tcp_listener = tcp_listener.expect("TCP listener");
        let udp_socket = udp_socket.expect("UDP socket");

        // ---- Task: TUN ↔ Stack (SINGLE task, NO split, NO BiLock) ----
        // Owns the Stack directly. Biased select prioritizes outgoing packets
        // so SYN-ACK and response data reach the client ASAP.
        {
            let tun = tun.clone();
            let shutdown_rx = shutdown_rx.clone();
            let mut stack = stack;

            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; mtu as usize + 4];

                loop {
                    if *shutdown_rx.borrow() {
                        return;
                    }

                    tokio::select! {
                        biased;

                        // Priority 1: deliver outgoing packets from stack to TUN
                        frame = stack.next() => {
                            match frame {
                                Some(Ok(data)) => tun.write(data.as_ref()),
                                Some(Err(e)) => tracing::debug!("stack stream error: {e}"),
                                None => return,
                            }
                        }

                        // Priority 2: read from TUN, inject into stack
                        result = tun.read(&mut buf) => {
                            match result {
                                Ok(n) if n > 0 => {
                                    let pkt = &buf[..n];

                                    // ICMP interception
                                    if let Some(reply) = icmp::handle_icmp_echo(pkt) {
                                        tun.write(&reply);
                                        ICMP_REPLIES.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }

                                    let frame: netstack_smoltcp::AnyIpPktFrame =
                                        pkt.to_vec().into();
                                    if let Err(e) = stack.send(frame).await {
                                        tracing::debug!("stack sink error: {e}");
                                    }
                                }
                                Err(e) if !*shutdown_rx.borrow() => {
                                    tracing::debug!("TUN read error: {e}");
                                }
                                _ => {}
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
            let active: Arc<Mutex<HashSet<(SocketAddr, SocketAddr)>>> =
                Arc::new(Mutex::new(HashSet::new()));

            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        conn = tcp_listener.next() => {
                            match conn {
                                Some((stream, local_addr, remote_addr)) => {
                                    let key = (local_addr, remote_addr);
                                    {
                                        let mut set = active.lock().await;
                                        if !set.insert(key) { continue; }
                                    }
                                    let proxy = proxy.clone();
                                    let active = active.clone();
                                    tokio::spawn(async move {
                                        handle_tcp(stream, local_addr, remote_addr, proxy).await;
                                        active.lock().await.remove(&key);
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
                            let Some((payload, local_addr, remote_addr)) = msg else { return; };
                            let src = local_addr;
                            let dst = remote_addr;
                            let key = (src, dst);
                            let proxy = proxy.clone();
                            let sessions = sessions.clone();
                            let udp_write = udp_write.clone();

                            tokio::spawn(async move {
                                let existing = sessions.lock().await.get(&key).cloned();
                                if let Some(tx) = existing {
                                    let _ = tx.send(payload).await;
                                } else {
                                    ACTIVE_UDP_RELAYS.fetch_add(1, Ordering::Relaxed);
                                    let session = match proxy.new_udp_session(dst).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!("[UDP] dial {src}->{dst}: {e}");
                                            UDP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
                                            ACTIVE_UDP_RELAYS.fetch_sub(1, Ordering::Relaxed);
                                            return;
                                        }
                                    };
                                    tracing::info!("[UDP] {src} <-> {dst}");
                                    let tx = session.outgoing.clone();
                                    sessions.lock().await.insert(key, session.outgoing);
                                    let _ = tx.send(payload).await;

                                    let cleanup = sessions.clone();
                                    let uw = udp_write.clone();
                                    tokio::spawn(async move {
                                        let mut rx = session.incoming;
                                        loop {
                                            match tokio::time::timeout(UDP_SESSION_TIMEOUT, rx.recv()).await {
                                                Ok(Some(data)) => {
                                                    if uw.lock().await.send((data, src, dst)).await.is_err() { break; }
                                                }
                                                _ => break,
                                            }
                                        }
                                        cleanup.lock().await.remove(&key);
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

        Ok(Self { shutdown: shutdown_tx, tasks, _tun: tun })
    }

    pub async fn close(self) {
        let _ = self.shutdown.send(true);
        for t in self.tasks { t.abort(); let _ = t.await; }
    }
}

async fn handle_tcp(
    tcp_stream: netstack_smoltcp::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    proxy: Arc<SsProxy>,
) {
    ACTIVE_TCP_RELAYS.fetch_add(1, Ordering::Relaxed);
    struct G; impl Drop for G { fn drop(&mut self) { ACTIVE_TCP_RELAYS.fetch_sub(1, Ordering::Relaxed); } }
    let _g = G;

    let src = local_addr;
    let target = remote_addr;
    let start = Instant::now();

    let remote = match proxy.dial_tcp(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[TCP] dial {src}->{target}: {e}");
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    tracing::info!("[TCP] relay {src} <-> {target}");

    if let Err(e) = relay_tcp(tcp_stream, remote).await {
        if e.kind() == io::ErrorKind::TimedOut {
            TCP_RELAY_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        } else {
            TCP_RELAY_ERRORS.fetch_add(1, Ordering::Relaxed);
            tracing::info!("[TCP] err {src}<->{target} {:?}: {e}", start.elapsed());
        }
    } else {
        tracing::info!("[TCP] done {src}<->{target} {:?}", start.elapsed());
    }
}

async fn relay_tcp<A, B>(mut a: A, mut b: B) -> io::Result<()>
where A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(&mut a);
    let (mut br, mut bw) = tokio::io::split(&mut b);
    tokio::select! {
        r = copy_timeout(&mut ar, &mut bw) => r?,
        r = copy_timeout(&mut br, &mut aw) => r?,
    };
    Ok(())
}

async fn copy_timeout<R, W>(r: &mut R, w: &mut W) -> io::Result<u64>
where R: AsyncRead + Unpin, W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; TCP_RELAY_BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = match tokio::time::timeout(TCP_IDLE_TIMEOUT, r.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(total),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "idle")),
        };
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        total += n as u64;
    }
}
