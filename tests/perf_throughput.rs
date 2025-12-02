use std::io::{Read, Write};
use vpn_server::enroll_http;

#[test]
fn perf_throughput_download_perf_bin() {
    std::env::set_var("VPN_HTTP_BIND", "127.0.0.1");
    std::env::set_var("PERF_BYTES", "20000000"); // 20 MB
    enroll_http::spawn_enroll_server();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let start = std::time::Instant::now();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", 8080)).unwrap();
    let req = "GET /__perf.bin HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let elapsed = start.elapsed().as_secs_f64();
    // crude header split to approximate body length
    let header_end = resp.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let bytes = (resp.len().saturating_sub(header_end)) as f64;
    let mbps = (bytes * 8.0) / (elapsed * 1_000_000.0);
    println!("throughput_mbps={:.2}", mbps);
    assert!(mbps > 50.0);
}
