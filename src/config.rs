use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{bail, Context, Result};

const DEFAULT_CONCURRENCY: usize = 4;
const DEFAULT_MTU: u16 = 1500;

/// Parse a boolean string value.
/// Accepts: true/false, yes/no, 1/0 (case-insensitive).
/// Returns an error for unknown values to avoid silent misconfiguration.
pub fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => bail!("boolean value expected, got '{s}'"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfsMode {
    Disable,
    SimpleObfs,
    Xray,
}

#[derive(Debug, Clone)]
pub struct Config {
    // Network
    pub gateway: String,
    pub gateway6: String,
    pub interface: String,
    pub default_gateway: String,
    pub default_interface: String,
    pub concurrency: usize,
    pub mtu: u16, // 0 = auto

    // Shadowsocks
    pub ss_enabled: bool,
    pub ss_server: String,
    pub ss_server_port: u16,
    pub ss_password: String,
    pub ss_method: String,

    // Obfuscation
    pub obfs_mode: ObfsMode,
    pub obfs_host: String,

    // V2Ray plugin (when obfs_mode == V2ray)
    pub ss_plugin: String,
    pub ss_plugin_opts: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway: String::new(),
            gateway6: String::new(),
            interface: String::new(),
            default_gateway: String::new(),
            default_interface: String::new(),
            concurrency: DEFAULT_CONCURRENCY,
            mtu: 0,

            ss_enabled: false,
            ss_server: String::new(),
            ss_server_port: 0,
            ss_password: String::new(),
            ss_method: "aes-256-gcm".to_string(),

            obfs_mode: ObfsMode::Disable,
            obfs_host: String::new(),

            ss_plugin: String::new(),
            ss_plugin_opts: String::new(),
        }
    }
}

pub fn read_config(path: &Path) -> Result<Config> {
    let file = File::open(path).with_context(|| format!("open config file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut config = Config::default();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read line {}", line_num + 1))?;
        let line = line.trim().to_string();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        if value.is_empty() {
            continue;
        }

        match key {
            "gateway" => config.gateway = value.to_string(),
            "gateway6" => config.gateway6 = value.to_string(),
            "interface" => config.interface = value.to_string(),
            "default_gw" => config.default_gateway = value.to_string(),
            "default_interface" => config.default_interface = value.to_string(),
            "goroutine_count" | "concurrency" => {
                config.concurrency = value
                    .parse()
                    .with_context(|| format!("invalid concurrency value '{value}'"))?;
            }
            "mtu" => {
                config.mtu = value
                    .parse()
                    .with_context(|| format!("invalid mtu value '{value}'"))?;
            }
            "ss_enabled" => {
                config.ss_enabled = parse_bool(value)?;
            }
            "ss_server" => config.ss_server = value.to_string(),
            "ss_server_port" => {
                config.ss_server_port = value
                    .parse()
                    .with_context(|| format!("invalid ss_server_port value '{value}'"))?;
            }
            "ss_password" => config.ss_password = value.to_string(),
            "ss_method" => config.ss_method = value.to_string(),
            "obfs_mode" => {
                config.obfs_mode = match value {
                    "disable" | "" => ObfsMode::Disable,
                    "simple-obfs" => ObfsMode::SimpleObfs,
                    "v2ray" | "xray" => ObfsMode::Xray,
                    _ => bail!("unknown obfs_mode: {value}"),
                };
            }
            "obfs_host" => config.obfs_host = value.to_string(),
            "ss_plugin" => config.ss_plugin = value.to_string(),
            "ss_plugin_opts" => config.ss_plugin_opts = value.to_string(),
            _ => {} // unknown keys silently ignored
        }
    }

    // Auto-detect MTU if not set
    if config.mtu == 0 {
        config.mtu = DEFAULT_MTU;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_parse_minimal_config() {
        let f = write_temp_config("gateway=10.0.0.1\ninterface=tun2\n");
        let config = read_config(f.path()).unwrap();
        assert_eq!(config.gateway, "10.0.0.1");
        assert_eq!(config.interface, "tun2");
        assert_eq!(config.concurrency, 4);
        assert!(!config.ss_enabled);
        assert_eq!(config.mtu, DEFAULT_MTU);
    }

    #[test]
    fn test_parse_full_config() {
        let f = write_temp_config(
            "gateway=10.0.0.1\n\
             interface=tun2\n\
             default_gw=192.168.1.1\n\
             default_interface=eth0\n\
             concurrency=100\n\
             mtu=1400\n\
             ss_enabled=true\n\
             ss_server=1.2.3.4\n\
             ss_server_port=8388\n\
             ss_password=secret\n\
             ss_method=chacha20-ietf-poly1305\n\
             obfs_mode=xray\n\
             obfs_host=www.bing.com\n\
             ss_plugin=xray-plugin\n\
             ss_plugin_opts=server;tls;host=example.com\n",
        );
        let config = read_config(f.path()).unwrap();
        assert_eq!(config.gateway, "10.0.0.1");
        assert_eq!(config.default_gateway, "192.168.1.1");
        assert_eq!(config.default_interface, "eth0");
        assert_eq!(config.concurrency, 100);
        assert_eq!(config.mtu, 1400);
        assert!(config.ss_enabled);
        assert_eq!(config.ss_server, "1.2.3.4");
        assert_eq!(config.ss_server_port, 8388);
        assert_eq!(config.ss_password, "secret");
        assert_eq!(config.ss_method, "chacha20-ietf-poly1305");
        assert_eq!(config.obfs_mode, ObfsMode::Xray);
        assert_eq!(config.obfs_host, "www.bing.com");
        assert_eq!(config.ss_plugin, "xray-plugin");
        assert_eq!(config.ss_plugin_opts, "server;tls;host=example.com");
    }

    #[test]
    fn test_comments_and_blanks() {
        let f = write_temp_config("# comment\n\ngateway=10.0.0.1\n  # another\n");
        let config = read_config(f.path()).unwrap();
        assert_eq!(config.gateway, "10.0.0.1");
    }

    #[test]
    fn test_empty_values_skipped() {
        let f = write_temp_config("gateway=\ninterface=tun0\n");
        let config = read_config(f.path()).unwrap();
        assert_eq!(config.gateway, ""); // default empty
        assert_eq!(config.interface, "tun0");
    }

    #[test]
    fn test_ipv6_gateway() {
        let f = write_temp_config("gateway=10.0.0.1\ngateway6=2001:db8::1\ninterface=tun2\n");
        let config = read_config(f.path()).unwrap();
        assert_eq!(config.gateway, "10.0.0.1");
        assert_eq!(config.gateway6, "2001:db8::1");
    }

    #[test]
    fn test_ipv6_gateway6() {
        let f = write_temp_config("gateway6=2001:db8::2\ninterface=tun2\n");
        let config = read_config(f.path()).unwrap();
        assert_eq!(config.gateway6, "2001:db8::2");
    }

    #[test]
    fn test_ss_enabled_variants() {
        let test_cases = vec![
            ("true", true),
            ("false", false),
            ("True", true),
            ("FALSE", false),
            ("yes", true),
            ("no", false),
            ("Yes", true),
            ("No", false),
            ("1", true),
            ("0", false),
        ];
        for (input, expected) in test_cases {
            let f = write_temp_config(&format!("gateway=10.0.0.1\ninterface=tun2\nss_enabled={}\n", input));
            let config = read_config(f.path()).unwrap();
            assert_eq!(config.ss_enabled, expected, "ss_enabled={}", input);
        }
    }

    #[test]
    fn test_ss_enabled_invalid_value() {
        let test_cases = vec!["tru", "ye", "Falsey", "1.0", "on", "off"];
        for input in test_cases {
            let f = write_temp_config(&format!("gateway=10.0.0.1\ninterface=tun2\nss_enabled={}\n", input));
            let result = read_config(f.path());
            assert!(result.is_err(), "ss_enabled={} should fail", input);
        }
    }
}
