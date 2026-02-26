use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context as SsContext, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks::relay::Address;
use shadowsocks::ServerAddr;

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
            .with_context(|| format!("invalid SS server address: {addr}"))?;

        let svr_cfg = ServerConfig::new(server_addr, password, cipher);
        let context = SsContext::new_shared(ServerType::Local);

        Ok(Self {
            context,
            server_config: Arc::new(svr_cfg),
        })
    }

    /// Dial a TCP connection through the Shadowsocks server to the given target.
    pub async fn dial_tcp(
        &self,
        target: SocketAddr,
    ) -> Result<ProxyClientStream<tokio::net::TcpStream>> {
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

    /// Create a UDP proxy socket through the Shadowsocks server.
    pub async fn dial_udp(
        &self,
    ) -> Result<shadowsocks::relay::udprelay::proxy_socket::ProxySocket> {
        let socket = shadowsocks::relay::udprelay::proxy_socket::ProxySocket::connect(
            self.context.clone(),
            &*self.server_config,
        )
        .await
        .context("SS UDP connect")?;

        Ok(socket)
    }
}
