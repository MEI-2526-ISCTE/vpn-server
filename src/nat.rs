use std::process::Command;

pub fn setup_nat(interface: &str, uplink: Option<&str>) {
    if cfg!(target_os = "linux") {
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();
        let uplink = uplink.unwrap_or("eth0");
        // Idempotent iptables rules
        let check_nat = Command::new("iptables").args(["-t", "nat", "-C", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"]).output();
        if check_nat.is_err() || !check_nat.as_ref().unwrap().status.success() {
            let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"]).output();
        }
        let check_fwd_in = Command::new("iptables").args(["-C", "FORWARD", "-i", interface, "-j", "ACCEPT"]).output();
        if check_fwd_in.is_err() || !check_fwd_in.as_ref().unwrap().status.success() {
            let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", interface, "-j", "ACCEPT"]).output();
        }
        let check_fwd_out = Command::new("iptables").args(["-C", "FORWARD", "-o", interface, "-j", "ACCEPT"]).output();
        if check_fwd_out.is_err() || !check_fwd_out.as_ref().unwrap().status.success() {
            let _ = Command::new("iptables").args(["-A", "FORWARD", "-o", interface, "-j", "ACCEPT"]).output();
        }
    } else if cfg!(target_os = "windows") {
        let _ = Command::new("netsh").args(["interface", "ipv4", "set", "interface", interface, "forwarding=enabled"]).output();
        let _ = Command::new("powershell").args([
            "-Command",
            "if (!(Get-NetNat -Name 'WireGuardNAT' -ErrorAction SilentlyContinue)) { New-NetNat -Name 'WireGuardNAT' -InternalIPInterfaceAddressPrefix 10.8.0.0/24 }",
        ]).output();
        let _ = Command::new("powershell").args([
            "-Command",
            "if (-not (Get-NetFirewallRule -DisplayName 'WireGuard UDP 51820' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'WireGuard UDP 51820' -Direction Inbound -Protocol UDP -LocalPort 51820 -Action Allow }",
        ]).output();
    }
}
