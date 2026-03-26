use std::time::Duration;

use anyhow::{Context, Result};
use shadowsocks_service::config::{
    Config as SsConfig, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType,
    ServerInstanceConfig,
};
use shadowsocks_service::shadowsocks::config::{Mode, ServerAddr, ServerConfig};
use shadowsocks_service::shadowsocks::crypto::CipherKind;

use crate::config::Config;

/// Build a shadowsocks-service Config from our app Config.
pub fn build_ss_config(config: &Config) -> Result<SsConfig> {
    let cipher: CipherKind = config
        .ss_method
        .parse()
        .map_err(|_| anyhow::anyhow!("unknown cipher: {}", config.ss_method))?;

    let ss_addr = format!("{}:{}", config.ss_server, config.ss_server_port);
    let server_addr: ServerAddr = ss_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid SS server address '{ss_addr}': {e:?}"))?;

    let svr_cfg = ServerConfig::new(server_addr, &config.ss_password, cipher)
        .map_err(|e| anyhow::anyhow!("invalid SS config: {e:?}"))?;

    let mut ss_config = SsConfig::new(ConfigType::Local);

    // Add the SS server
    ss_config
        .server
        .push(ServerInstanceConfig::with_server_config(svr_cfg));

    // Configure TUN local
    let mut local = LocalConfig::new(ProtocolType::Tun);
    local.mode = Mode::TcpAndUdp;
    local.tun_interface_name = Some(config.interface.clone());

    // Parse address as IpNet
    let addr_cidr = format!("{}/{}", config.gateway, if config.gateway.contains(':') { 64 } else { 24 });
    local.tun_interface_address = Some(
        addr_cidr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid TUN address '{addr_cidr}': {e}"))?,
    );

    ss_config
        .local
        .push(LocalInstanceConfig::with_local_config(local));

    // UDP settings
    ss_config.udp_timeout = Some(Duration::from_secs(120));

    Ok(ss_config)
}

/// Start the shadowsocks local TUN service.
pub async fn run_service(ss_config: SsConfig) -> Result<()> {
    shadowsocks_service::local::run(ss_config)
        .await
        .context("shadowsocks local service")?;
    Ok(())
}
