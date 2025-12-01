use std::io::{Read, Write};
use vpn_server::{enroll_http, config};
use base64::Engine as _;

#[test]
fn enroll_success_returns_json_with_keys() {
    let _ = std::fs::remove_file("server.toml");
    let cfg = config::ensure_server_keys(config::load_server_config(None).unwrap(), None).unwrap();
    std::env::set_var("VPN_HTTP_BIND", "127.0.0.1");
    enroll_http::spawn_enroll_server();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // generate a fresh public key
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    // POST /enroll
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", 8080)).unwrap();
    let req = format!(
        "POST /enroll HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        pub_b64.len(), pub_b64
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"));
    assert!(resp.contains("Content-Type: application/json"));
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(body.contains("server_public_key_b64"));
    assert!(body.contains("listen_port"));
    let _ = cfg; // silence unused variable in some toolchains
}
