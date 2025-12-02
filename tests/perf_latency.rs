use std::io::{Read, Write};
use vpn_server::enroll_http;

#[test]
fn perf_latency_ping_50_requests() {
    std::env::set_var("VPN_HTTP_BIND", "127.0.0.1");
    enroll_http::spawn_enroll_server();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut times = Vec::new();
    for _ in 0..50 {
        let start = std::time::Instant::now();
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", 8080)).unwrap();
        let req = "GET /__ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        let dt = start.elapsed();
        assert!(resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"));
        assert!(resp.contains("pong"));
        times.push(dt);
    }
    let sum = times.iter().map(|d| d.as_millis() as u128).sum::<u128>();
    let avg = (sum as f64) / (times.len() as f64);
    let min = times.iter().map(|d| d.as_millis()).min().unwrap();
    let max = times.iter().map(|d| d.as_millis()).max().unwrap();
    println!("latency_ms avg={:.2} min={} max={}", avg, min, max);
    assert!(avg < 100.0);
}

