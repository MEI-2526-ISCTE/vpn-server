use crate::config::{PeerConfig, ServerConfig};
use base64::engine::general_purpose;
use base64::Engine as _;
use std::{net::Ipv4Addr, path::PathBuf};

/**
 * @brief List peers from configuration.
 * @param cfg Server configuration.
 * @return Vector of PeerConfig entries.
 */
pub fn list_peers(cfg: &ServerConfig) -> Vec<PeerConfig> {
    cfg.peers.clone()
}

/**
 * @brief Add a peer to the server configuration, allocating the next IP.
 * @param cfg Current server configuration.
 * @param public_key_b64 Peer public key (Base64-encoded, 32 bytes).
 * @return Updated ServerConfig.
 */
pub fn add_peer(mut cfg: ServerConfig, public_key_b64: String) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let used: Vec<String> = cfg.peers.iter().map(|p| p.address_cidr.clone()).collect();
    let next = allocate_ip(&used)?;
    let pc = PeerConfig {
        public_key_b64,
        address_cidr: format!("{}/32", next),
        allowed_ips: vec![],
    };
    cfg.peers.push(pc);
    persist(&cfg)?;
    Ok(cfg)
}

/**
 * @brief Remove a peer from the server configuration.
 * @param cfg Current server configuration.
 * @param public_key_b64 Peer public key to remove.
 * @return Updated ServerConfig.
 */
pub fn remove_peer(mut cfg: ServerConfig, public_key_b64: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    cfg.peers.retain(|p| p.public_key_b64 != public_key_b64);
    persist(&cfg)?;
    Ok(cfg)
}

/**
 * @brief Allocate the next available IPv4 address in 10.8.0.0/24.
 * @param used List of used CIDR strings.
 * @return Next free IPv4 address, or error if exhausted.
 */
fn allocate_ip(used: &[String]) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let _base = Ipv4Addr::new(10, 8, 0, 2);
    for last in 2..=254u8 {
        let candidate = Ipv4Addr::new(10, 8, 0, last);
        let cidr = format!("{}/32", candidate);
        if !used.contains(&cidr) {
            return Ok(candidate);
        }
    }
    Err("No available IPs".into())
}

/**
 * @brief Persist server configuration to `server.toml`.
 * @param cfg Server configuration.
 */
fn persist(cfg: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let p = PathBuf::from("server.toml");
    let s = toml::to_string_pretty(cfg)?;
    std::fs::write(p, s)?;
    Ok(())
}

/**
 * @brief Validate a Base64 public key decodes to 32 bytes.
 * @param b64 Base64-encoded public key.
 */
pub fn validate_public_key_b64(b64: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = general_purpose::STANDARD.decode(b64)?;
    if bytes.len() != 32 { return Err("Invalid public key length".into()); }
    Ok(())
}
