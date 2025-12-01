use crate::config::ServerConfig;
use base64::{engine::general_purpose, Engine as _};
use defguard_wireguard_rs::{host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration};
use std::str::FromStr;

pub fn peers_from_config(cfg: &ServerConfig) -> Result<Vec<(Peer, Key)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for pc in cfg.peers.iter() {
        let pk_bytes = general_purpose::STANDARD.decode(&pc.public_key_b64)?;
        let pk: [u8; 32] = pk_bytes.try_into().map_err(|_| "Invalid key length")?;
        let k = Key::new(pk);
        let mut p = Peer::new(k.clone());
        p.allowed_ips.push(IpAddrMask::from_str(&pc.address_cidr)?);
        for aip in &pc.allowed_ips { p.allowed_ips.push(IpAddrMask::from_str(aip)?); }
        out.push((p, k));
    }
    Ok(out)
}

pub fn interface_config(
    cfg: &ServerConfig,
    ifname: &str,
    server_privkey_b64: &str,
    peers: &[(Peer, Key)],
) -> Result<InterfaceConfiguration, Box<dyn std::error::Error>> {
    Ok(InterfaceConfiguration {
        name: ifname.to_string(),
        prvkey: server_privkey_b64.to_string(),
        addresses: vec![cfg.address_cidr.parse()?],
        port: cfg.listen_port as u32,
        peers: peers.iter().map(|(p, _)| p.clone()).collect(),
        mtu: None,
    })
}
