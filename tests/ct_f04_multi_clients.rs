use vpn_server::{config, peer_registry};
use base64::Engine as _;

#[test]
fn ct_f04_multiple_clients_can_be_added() {
    let _ = std::fs::remove_file("server.toml");
    let mut cfg = config::load_server_config(None).unwrap();
    let keys: Vec<String> = (0..10).map(|_i| {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        base64::engine::general_purpose::STANDARD.encode(public.as_bytes())
    }).collect();
    for k in &keys { cfg = peer_registry::add_peer(cfg.clone(), k.clone()).unwrap(); }
    assert!(cfg.peers.len() >= 10);
}
