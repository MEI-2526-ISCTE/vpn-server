/* \page ServerOverview Server Overview
WireGuard VPN server components.

- Configuration loading and key management (`config.rs`).
- Peer registry and IP allocation (`peer_registry.rs`).
- Interface configuration utilities (`wg.rs`).
- Runtime orchestration (`runtime.rs`).
- Enrollment HTTP server for auto-enroll (`enroll_http.rs`).
*/
pub mod config;
pub mod peer_registry;
pub mod nat;
pub mod wg;
pub mod runtime;
pub mod enroll_http;
pub mod filelog;
