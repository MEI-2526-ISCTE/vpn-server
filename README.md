# VPN Server

## Usage
- Build: `cargo build`
- Initialize config and keys: `./target/debug/vpn-server init`
- Add a peer: `./target/debug/vpn-server add-peer <client_public_key_b64>`
- List peers: `./target/debug/vpn-server list-peers`
- Start server: `sudo ./target/debug/vpn-server start`
- Show status: `./target/debug/vpn-server status`
- Export client config (with QR): `./target/debug/vpn-server export-client-config <client_public_key_b64>`
