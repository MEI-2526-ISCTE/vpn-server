use std::{
    collections::HashMap, process::Command, str::FromStr, sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::{Duration, Instant}
};

use base64::{engine::general_purpose, Engine as _};
use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WGApi, WireguardInterfaceApi,
};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nCtrl+C received — shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    let ifname = "wg-server".to_string();  // Changed to avoid conflict with client
    println!("Creating WireGuard interface: {ifname}");

    let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
    wgapi.create_interface()?;

    // === SERVER KEYS (fixed) ===
    let server_privkey_b64 = "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=";
    let server_privkey_bytes = general_purpose::STANDARD.decode(server_privkey_b64)?;
    let server_privkey_bytes: [u8; 32] = server_privkey_bytes.try_into().map_err(|_| "Invalid key length")?;
    let server_secret = StaticSecret::from(server_privkey_bytes);
    let server_public = PublicKey::from(&server_secret);
    let server_public_key = Key::new(*server_public.as_bytes());

    // === FIXED CLIENT PEER (matching client's public key) ===
    let mut peers = Vec::new();
    let client_pubkey_b64 = "SBGX26d2F9aECQ7zMD4nUu90T3gPZvNzTara/iS2CW4=";  // Client's public key
    let client_pubkey_bytes = general_purpose::STANDARD.decode(client_pubkey_b64)?;
    let client_pubkey_bytes: [u8; 32] = client_pubkey_bytes.try_into().map_err(|_| "Invalid key length")?;
    let client_pubkey = Key::new(client_pubkey_bytes);

    let mut peer = Peer::new(client_pubkey.clone());
    peer.allowed_ips.push(IpAddrMask::from_str("10.8.0.2/32")?);
    peers.push((peer, client_pubkey));

    // === APPLY CONFIG ===
    let config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: server_privkey_b64.to_string(),
        addresses: vec!["10.8.0.1/24".parse()?],
        port: 51820,
        peers: peers.iter().map(|(p, _)| p.clone()).collect(),
        mtu: None,
    };

    println!("Starting WireGuard server...");
    wgapi.configure_interface(&config)?;

    println!("WireGuard server is LIVE on UDP 51820!");
    println!("Server public key: {}", general_purpose::STANDARD.encode(server_public.as_bytes()));
    println!("Server running. Press Ctrl+C to stop.");

    let mut last_seen: HashMap<Key, Instant> = HashMap::new();

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(2));

        if let Ok(data) = wgapi.read_interface_data() {
            let mut currently_connected = HashMap::new();

            for (peer_key, peer_info) in &data.peers {
                let peer_ip = peer_info
                    .allowed_ips
                    .first()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                if let Some(_handshake) = peer_info.last_handshake {
                    let now = Instant::now();
                    currently_connected.insert(peer_key.clone(), now);

                    if !last_seen.contains_key(peer_key) {
                        println!(
                            "NEW CONNECTION from {} ({})",
                            peer_ip,
                            general_purpose::STANDARD.encode(peer_key.as_slice())
                        );
                    }

                    last_seen.insert(peer_key.clone(), now);
                }
            }

            // Detect clients that disappeared for >3 minutes
            let disconnected: Vec<Key> = last_seen
                .keys()
                .filter(|k| !currently_connected.contains_key(k))
                .cloned()
                .collect();

            for key in disconnected {
                if last_seen.get(&key).unwrap().elapsed() > Duration::from_secs(180) {
                    let ip = data
                        .peers
                        .get(&key)
                        .and_then(|p| p.allowed_ips.first())
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    println!(
                        "CLIENT DISCONNECTED → {} ({})",
                        ip,
                        general_purpose::STANDARD.encode(key.as_slice())
                    );
                    last_seen.remove(&key);
                }
            }
        }
    }

    // === CLEAN SHUTDOWN ===
    println!("Shutting down...");
    for (_, key) in peers {
        let _ = wgapi.remove_peer(&key);
    }

    let _ = Command::new("ip").args(["link", "set", &ifname, "down"]).output();
    let _ = Command::new("ip").args(["addr", "flush", "dev", &ifname]).output();
    wgapi.remove_interface()?;
    println!("Server stopped cleanly.");

    Ok(())
}