use serde::{Deserialize, Serialize};
use base64::Engine as _;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key_b64: String,
    pub address_cidr: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub interface_name: String,
    pub address_cidr: String,
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
    pub nat_enabled: bool,
    pub uplink_iface: Option<String>,
    pub server_private_key_b64: Option<String>,
    pub auto_enroll_dir: Option<String>,
    pub static_dir: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            interface_name: "wg-server".into(),
            address_cidr: "10.8.0.1/24".into(),
            listen_port: 51820,
            peers: Vec::new(),
            nat_enabled: true,
            uplink_iface: None,
            server_private_key_b64: None,
            auto_enroll_dir: Some("enroll".into()),
            static_dir: Some("public".into()),
        }
    }
}

/**
 * @brief Load server configuration from `server.toml`, creating defaults when missing.
 * @param path Optional path override for the configuration file.
 * @return Parsed ServerConfig.
 */
pub fn load_server_config(path: Option<PathBuf>) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let p = path.unwrap_or_else(|| PathBuf::from("server.toml"));
    if !p.exists() {
        let def = ServerConfig::default();
        let s = toml::to_string_pretty(&def)?;
        fs::write(&p, s)?;
        return Ok(def);
    }
    let s = fs::read_to_string(p)?;
    let cfg: ServerConfig = toml::from_str(&s)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creates_default_when_missing() {
        let p = PathBuf::from("server.toml");
        let _ = std::fs::remove_file(&p);
        let cfg = load_server_config(Some(p.clone())).unwrap();
        assert_eq!(cfg.interface_name, "wg-server");
        assert!(p.exists());
    }
}

/**
 * @brief Ensure server private key exists; generate and persist if missing.
 * @param cfg Current server configuration.
 * @param path Optional path override for the configuration file.
 * @return Updated ServerConfig with private key set.
 */
pub fn ensure_server_keys(mut cfg: ServerConfig, path: Option<PathBuf>) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    if cfg.server_private_key_b64.is_some() {
        return Ok(cfg);
    }
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode(secret.to_bytes());
    cfg.server_private_key_b64 = Some(priv_b64);
    let p = path.unwrap_or_else(|| PathBuf::from("server.toml"));
    let s = toml::to_string_pretty(&cfg)?;
    fs::write(p, s)?;
    println!("Server public key: {}", base64::engine::general_purpose::STANDARD.encode(public.as_bytes()));
    Ok(cfg)
}
