use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context as SsContext, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks::relay::Address;
use shadowsocks::ServerAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Shadowsocks proxy wrapper for TCP and UDP connections.
#[derive(Clone)]
pub struct SsProxy {
    context: SharedContext,
    server_config: Arc<ServerConfig>,
}

impl SsProxy {
    /// Create a new SS proxy.
    /// `addr` is "host:port" of the SS server (or plugin local address).
    /// `method` is the cipher name (e.g. "aes-256-gcm").
    pub fn new(addr: &str, method: &str, password: &str) -> Result<Self> {
        let cipher: CipherKind = method
            .parse()
            .map_err(|_| anyhow::anyhow!("unknown cipher: {method}"))?;

        let server_addr: ServerAddr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid SS server address '{addr}': {e:?}"))?;

        let svr_cfg = ServerConfig::new(server_addr, password, cipher)
            .map_err(|e| anyhow::anyhow!("invalid SS server config: {e:?}"))?;

        let context = SsContext::new_shared(ServerType::Local);

        Ok(Self {
            context,
            server_config: Arc::new(svr_cfg),
        })
    }

    /// Dial a TCP connection through the Shadowsocks server to the given target.
    /// Returns a stream that implements AsyncRead + AsyncWrite.
    pub async fn dial_tcp(
        &self,
        target: SocketAddr,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin> {
        let addr = Address::SocketAddress(target);
        let stream = ProxyClientStream::connect(
            self.context.clone(),
            &*self.server_config,
            &addr,
        )
        .await
        .with_context(|| format!("SS TCP dial to {target}"))?;

        Ok(stream)
    }

    /// Create a new UDP session: spawns a task that relays between a local channel
    /// and the SS proxy. Returns a sender for outgoing packets and a receiver for
    /// incoming packets.
    pub async fn new_udp_session(
        &self,
        target: SocketAddr,
    ) -> Result<UdpSession> {
        let proxy_socket = shadowsocks::relay::udprelay::proxy_socket::ProxySocket::connect(
            self.context.clone(),
            &*self.server_config,
        )
        .await
        .context("SS UDP connect")?;

        let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        let addr = Address::SocketAddress(target);

        // Spawn a task that owns the ProxySocket
        let task = tokio::spawn(async move {
            let mut recv_buf = vec![0u8; 65536];

            loop {
                tokio::select! {
                    // Forward outgoing packets to SS
                    pkt = outgoing_rx.recv() => {
                        match pkt {
                            Some(data) => {
                                if let Err(e) = proxy_socket.send(&addr, &data).await {
                                    tracing::debug!("[UDP] SS send error: {e}");
                                    break;
                                }
                            }
                            None => break, // channel closed
                        }
                    }
                    // Receive packets from SS and forward back
                    result = proxy_socket.recv(&mut recv_buf) => {
                        match result {
                            Ok((n, _, _)) => {
                                if incoming_tx.send(recv_buf[..n].to_vec()).await.is_err() {
                                    break; // receiver dropped
                                }
                            }
                            Err(e) => {
                                tracing::debug!("[UDP] SS recv error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(UdpSession {
            outgoing: outgoing_tx,
            incoming: incoming_rx,
            _task: task,
        })
    }
}

/// A UDP session that communicates with the SS proxy via channels.
/// The actual ProxySocket is owned by a background task.
pub struct UdpSession {
    pub outgoing: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub incoming: tokio::sync::mpsc::Receiver<Vec<u8>>,
    _task: tokio::task::JoinHandle<()>,
}
