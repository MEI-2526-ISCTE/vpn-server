
use base64::{engine::general_purpose, Engine as _};
mod config;
use config::{load_server_config, ensure_server_keys};
mod peer_registry;
mod nat;
mod wg;
mod runtime;
mod enroll_http;
use clap::{Parser, Subcommand};
use defguard_wireguard_rs::{WGApi, WireguardInterfaceApi};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => {
            let cfg = load_server_config(None)?;
            let _ = ensure_server_keys(cfg, None)?;
        }
        Cmd::AddPeer { public_key_b64 } => {
            peer_registry::validate_public_key_b64(&public_key_b64)?;
            let cfg = load_server_config(None)?;
            let _ = peer_registry::add_peer(cfg, public_key_b64)?;
        }
        Cmd::RemovePeer { public_key_b64 } => {
            let cfg = load_server_config(None)?;
            let _ = peer_registry::remove_peer(cfg, &public_key_b64)?;
        }
        Cmd::ListPeers => {
            let cfg = load_server_config(None)?;
            for p in peer_registry::list_peers(&cfg) {
                println!("{} {}", p.public_key_b64, p.address_cidr);
            }
        }
        Cmd::Status => {
            let cfg = load_server_config(None)?;
            let ifname = cfg.interface_name.clone();
            let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
            if let Ok(data) = wgapi.read_interface_data() {
                for (k, p) in &data.peers {
                    let pk = general_purpose::STANDARD.encode(k.as_slice());
                    let hs = p.last_handshake.is_some();
                    println!("{} {} {} KB {} KB", pk, hs, p.tx_bytes / 1024, p.rx_bytes / 1024);
                }
            }
        }
        Cmd::ExportClientConfig { public_key_b64: _ } => {
            let cfg = load_server_config(None)?;
            let ep = format!("127.0.0.1:{}", cfg.listen_port);
            let server_pub = {
                let b64 = cfg.server_private_key_b64.clone().unwrap();
                let bytes = general_purpose::STANDARD.decode(b64)?;
                let secret = StaticSecret::from(<[u8;32]>::try_from(bytes.as_slice()).unwrap());
                let public = PublicKey::from(&secret);
                general_purpose::STANDARD.encode(public.as_bytes())
            };
            let txt = format!("server_endpoint=\"{}\"\nserver_public_key_b64=\"{}\"\n", ep, server_pub);
            println!("{}", txt);
            let code = qrcode::QrCode::new(txt.as_bytes()).unwrap();
            let image = code.render::<char>().quiet_zone(false).module_dimensions(2, 1).build();
            println!("{}", image);
        }
        Cmd::Start => {
            runtime::start()?;
        }
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "vpn-server")]
#[command(version, about = "WireGuard VPN server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Init,
    Start,
    AddPeer { public_key_b64: String },
    RemovePeer { public_key_b64: String },
    ListPeers,
    Status,
    ExportClientConfig { public_key_b64: String },
}
