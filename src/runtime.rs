use crate::{config::{ensure_server_keys, load_server_config}, nat, wg};
use base64::{engine::general_purpose, Engine as _};
use defguard_wireguard_rs::{key::Key, InterfaceConfiguration, WGApi, WireguardInterfaceApi};
use std::{collections::HashMap, fs, path::PathBuf, process::Command, sync::{Arc, atomic::{AtomicBool, Ordering}} , thread, time::{Duration, Instant}};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(target_os = "windows")]
fn windows_preflight() -> Result<(), Box<dyn std::error::Error>> {
    let wg_ok = Command::new("wireguard.exe").arg("/version").output();
    if wg_ok.is_err() {
        return Err("WireGuard for Windows is not installed or not in PATH".into());
    }
    let admin_check = Command::new("net").arg("session").output();
    if let Ok(out) = admin_check {
        if out.status.code().unwrap_or(1) != 0 {
            return Err("Run the server as Administrator to install the tunnel service".into());
        }
    } else {
        return Err("Failed to check Administrator privileges".into());
    }
    Ok(())
}

fn scan_enroll_dir(cfg: &mut crate::config::ServerConfig, wgapi: &WGApi<defguard_wireguard_rs::Kernel>) -> Result<(), Box<dyn std::error::Error>> {
    let dir = cfg.auto_enroll_dir.clone().unwrap_or_else(|| "enroll".into());
    let p = PathBuf::from(&dir);
    if !p.exists() { fs::create_dir_all(&p)?; }
    for entry in fs::read_dir(&p)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() { continue; }
        let content = fs::read_to_string(&path)?;
        let pubkey_b64 = content.trim();
        if pubkey_b64.is_empty() { continue; }
        crate::peer_registry::validate_public_key_b64(pubkey_b64)?;
        if cfg.peers.iter().any(|pe| pe.public_key_b64 == pubkey_b64) {
            fs::remove_file(&path)?;
            continue;
        }
        let new_cfg = crate::peer_registry::add_peer(cfg.clone(), pubkey_b64.to_string())?;
        *cfg = new_cfg;
        // Reconfigure interface with updated peers (portable fallback)
        let peers_vec = crate::wg::peers_from_config(cfg)?;
        let cfg_ifname = cfg.interface_name.clone();
        let server_privkey_b64 = cfg.server_private_key_b64.clone().unwrap();
        let new_config: InterfaceConfiguration = crate::wg::interface_config(cfg, &cfg_ifname, &server_privkey_b64, &peers_vec)?;
        #[cfg(target_os = "windows")] { wgapi.configure_interface(&new_config, &[], &[])?; }
        #[cfg(not(target_os = "windows"))] { wgapi.configure_interface(&new_config)?; }
        fs::remove_file(&path)?;
        println!("Auto-enrolled peer {}", pubkey_b64);
    }
    Ok(())
}

pub fn start() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = windows_preflight() {
            eprintln!("Windows preflight failed: {}", e);
            return Err(e);
        }
    }
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || { println!("\nCtrl+C received — shutting down..."); r.store(false, Ordering::SeqCst); })?;
    let mut cfg = ensure_server_keys(load_server_config(None)?, None)?;
    let ifname = cfg.interface_name.clone();
    let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
    wgapi.create_interface()?;
    let server_privkey_b64 = cfg.server_private_key_b64.clone().unwrap();
    let server_privkey_bytes = general_purpose::STANDARD.decode(&server_privkey_b64)?;
    let server_privkey_bytes: [u8; 32] = server_privkey_bytes.try_into().map_err(|_| "Invalid key length")?;
    let server_secret = StaticSecret::from(server_privkey_bytes);
    let server_public = PublicKey::from(&server_secret);
    let peers_vec = wg::peers_from_config(&cfg)?;
    let config: InterfaceConfiguration = wg::interface_config(&cfg, &ifname, &server_privkey_b64, &peers_vec)?;
    #[cfg(target_os = "windows")] { wgapi.configure_interface(&config, &[], &[])?; }
    #[cfg(not(target_os = "windows"))] { wgapi.configure_interface(&config)?; }
    if cfg.nat_enabled { nat::setup_nat(&ifname, cfg.uplink_iface.as_deref()); }
    println!("WireGuard server is LIVE on UDP {}!", cfg.listen_port);
    println!("Server public key: {}", general_purpose::STANDARD.encode(server_public.as_bytes()));
    let mut last_seen: HashMap<Key, Instant> = HashMap::new();
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(2));
        scan_enroll_dir(&mut cfg, &wgapi)?;
        if let Ok(data) = wgapi.read_interface_data() {
            let mut currently_connected = HashMap::new();
            for (peer_key, peer_info) in &data.peers {
                let peer_ip = peer_info.allowed_ips.first().map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string());
                if let Some(handshake) = peer_info.last_handshake {
                    if handshake.elapsed().ok().map(|d| d < Duration::from_secs(15)).unwrap_or(false) {
                        let now = Instant::now();
                        currently_connected.insert(peer_key.clone(), now);
                        if !last_seen.contains_key(peer_key) {
                            println!("Client connected: {} ({})", peer_ip, general_purpose::STANDARD.encode(peer_key.as_slice()));
                        }
                        last_seen.insert(peer_key.clone(), now);
                    }
                }
            }
            let disconnected: Vec<Key> = last_seen.keys().filter(|k| !currently_connected.contains_key(k)).cloned().collect();
            for key in disconnected {
                if last_seen.get(&key).unwrap().elapsed() > Duration::from_secs(180) {
                    let ip = data.peers.get(&key).and_then(|p| p.allowed_ips.first()).map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string());
                    println!("Client disconnected: {} ({})", ip, general_purpose::STANDARD.encode(key.as_slice()));
                    last_seen.remove(&key);
                }
            }
        }
    }
    for (_, key) in peers_vec { let _ = wgapi.remove_peer(&key); }
    let _ = Command::new("ip").args(["link", "set", &ifname, "down"]).output();
    let _ = Command::new("ip").args(["addr", "flush", "dev", &ifname]).output();
    wgapi.remove_interface()?;
    println!("Server stopped cleanly.");
    Ok(())
}
