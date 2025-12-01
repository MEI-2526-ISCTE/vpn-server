use std::io::{Read, Write};
use vpn_server::{config, peer_registry, enroll_http};

#[test]
fn duplicate_enroll_redirects_to_root() {
    let _ = std::fs::remove_file("server.toml");
    let cfg = config::load_server_config(None).unwrap();
    let pub_b64 = "o1xtoMCHHFXtnsdwl3+GmUaPq+8OjscQLaO5xMSuf24=";
    let _cfg2 = peer_registry::add_peer(cfg, pub_b64.to_string()).unwrap();
    std::env::set_var("VPN_HTTP_BIND", "127.0.0.1");
    enroll_http::spawn_enroll_server();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", 8080)).unwrap();
    let req = format!(
        "POST /enroll HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        pub_b64.len(), pub_b64
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 303") || resp.starts_with("HTTP/1.0 303"));
    assert!(resp.contains("Location: /"));
}
