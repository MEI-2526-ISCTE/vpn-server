use vpn_server::{peer_registry, enroll_http};
use base64::Engine as _;

#[test]
fn ct_f05_validate_public_key_length() {
    let bad = "AAAA"; // too short
    assert!(peer_registry::validate_public_key_b64(bad).is_err());
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let ok = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    assert!(peer_registry::validate_public_key_b64(&ok).is_ok());
}

#[test]
fn ct_f05_enroll_invalid_key_returns_400() {
    enroll_http::spawn_enroll_server();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", 8080)).unwrap();
    let body = "AAAA";
    let req = format!(
        "POST /enroll HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    use std::io::Write; use std::io::Read;
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 400") || resp.starts_with("HTTP/1.0 400"));
}
