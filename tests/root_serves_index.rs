use std::io::{Read, Write};
use vpn_server::enroll_http;

#[test]
fn get_root_serves_index_html() {
    std::env::set_var("VPN_HTTP_BIND", "127.0.0.1");
    enroll_http::spawn_enroll_server();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", 8080)).unwrap();
    let req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"));
    assert!(resp.contains("Content-Type: text/html"));
    assert!(resp.split("\r\n\r\n").nth(1).map(|b| !b.is_empty()).unwrap_or(false));
}
