use std::fs;

#[test]
fn server_config_default_creates_file() {
    let p = std::path::Path::new("server.toml");
    let _ = fs::remove_file(p);
    let cfg = vpn_server::config::load_server_config(None).unwrap();
    assert!(p.exists());
    assert_eq!(cfg.interface_name, "wg-server");
}
