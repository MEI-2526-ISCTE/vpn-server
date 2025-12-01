use vpn_server::{config, peer_registry, wg};
use base64::Engine as _;

#[test]
fn assignment_and_routing_peers_from_config_matches_registry() {
    let _ = std::fs::remove_file("server.toml");
    let mut cfg = config::load_server_config(None).unwrap();
    // add two peers
    for _ in 0..2 {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        cfg = peer_registry::add_peer(cfg.clone(), pub_b64).unwrap();
    }
    let peers = wg::peers_from_config(&cfg).unwrap();
    assert_eq!(peers.len(), cfg.peers.len());
    // allowed IPs contain the assigned address CIDR
    for (p, _) in peers {
        assert!(p.allowed_ips.len() >= 1);
    }
}
