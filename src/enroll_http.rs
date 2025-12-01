use crate::{config::{load_server_config, ensure_server_keys}, peer_registry, wg};
use base64::{engine::general_purpose, Engine as _};
use tiny_http::{Server, Method, Response, Header};
use defguard_wireguard_rs::WireguardInterfaceApi;
use crate::filelog;
use std::{fs, path::PathBuf};

pub fn spawn_enroll_server() {
    std::thread::spawn(|| {
        let server = Server::http("0.0.0.0:8080").expect("Failed to bind enrollment HTTP server");
        loop {
            if let Ok(mut req) = server.recv() {
                if req.method() == &Method::Post && req.url() == "/enroll" {
                    let mut body = String::new();
                    let _ = req.as_reader().read_to_string(&mut body);
                    let pubkey_b64 = body.trim();
                    let mut cfg = match load_server_config(None) { Ok(c) => c, Err(e) => { let _ = req.respond(Response::from_string(format!("err: {}", e)).with_status_code(500)); continue; } };
                    if let Err(e) = peer_registry::validate_public_key_b64(pubkey_b64) {
                        let _ = req.respond(Response::from_string(format!("invalid: {}", e)).with_status_code(400));
                        continue;
                    }
                    if cfg.peers.iter().any(|p| p.public_key_b64 == pubkey_b64) {
                        let _ = req.respond(Response::from_string("ok").with_status_code(200));
                        continue;
                    }
                    cfg = match peer_registry::add_peer(cfg, pubkey_b64.to_string()) { Ok(n) => n, Err(e) => { let _ = req.respond(Response::from_string(format!("err: {}", e)).with_status_code(500)); continue; } };
                    let ifname = cfg.interface_name.clone();
                    let cfg = match ensure_server_keys(cfg, None) { Ok(c) => c, Err(e) => { let _ = req.respond(Response::from_string(format!("err: {}", e)).with_status_code(500)); continue; } };
                    let server_privkey_b64 = cfg.server_private_key_b64.clone().unwrap();
                    let peers_vec = match wg::peers_from_config(&cfg) { Ok(p) => p, Err(e) => { let _ = req.respond(Response::from_string(format!("err: {}", e)).with_status_code(500)); continue; } };
                    let config = match wg::interface_config(&cfg, &ifname, &server_privkey_b64, &peers_vec) { Ok(c) => c, Err(e) => { let _ = req.respond(Response::from_string(format!("err: {}", e)).with_status_code(500)); continue; } };
                    let wgapi = match defguard_wireguard_rs::WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone()) { Ok(a) => a, Err(e) => { let _ = req.respond(Response::from_string(format!("err: {}", e)).with_status_code(500)); continue; } };
                    #[cfg(target_os = "windows")] { let _ = wgapi.configure_interface(&config, &[], &[]); }
                    #[cfg(not(target_os = "windows"))] { let _ = wgapi.configure_interface(&config); }
                    let pub_bytes = general_purpose::STANDARD.decode(server_privkey_b64.clone()).unwrap();
                    let sk: [u8;32] = pub_bytes.try_into().unwrap();
                    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk));
                    let payload = serde_json::json!({
                        "server_public_key_b64": general_purpose::STANDARD.encode(public.as_bytes()),
                        "listen_port": cfg.listen_port,
                    });
                    let _ = req.respond(Response::from_string(payload.to_string()).with_status_code(200));
                    filelog::write_line("vpn-server.log", &format!("Auto-enrolled peer {}", pubkey_b64));
                } else if req.method() == &Method::Get || req.method() == &Method::Head {
                    // Resolve public directory relative to executable location for robustness
                    let base = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                        .unwrap_or_else(|| PathBuf::from("."));
                    let pub_dir = base.join("public");
                    let path = match req.url() {
                        "/" => pub_dir.join("index.html"),
                        other => {
                            let rel = other.trim_start_matches('/');
                            pub_dir.join(rel)
                        }
                    };
                    if let Ok(body) = fs::read(&path) {
                        let hdr = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                        let _ = req.respond(Response::from_data(body).with_header(hdr));
                    } else {
                        // Fallback to index.html
                        if let Ok(body) = fs::read(pub_dir.join("index.html")) {
                            let hdr = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                            let _ = req.respond(Response::from_data(body).with_header(hdr));
                        } else {
                            let _ = req.respond(Response::from_string("Not Found").with_status_code(404));
                        }
                    }
                } else {
                    // Acknowledge non-GET requests generically
                    let _ = req.respond(Response::from_string("ok").with_status_code(200));
                }
            }
        }
    });
}
