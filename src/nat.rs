use std::process::Command;

pub fn setup_nat(interface: &str, uplink: Option<&str>) {
    if cfg!(target_os = "linux") {
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();
        let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-o", uplink.unwrap_or("eth0"), "-j", "MASQUERADE"]).output();
        let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", interface, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(["-A", "FORWARD", "-o", interface, "-j", "ACCEPT"]).output();
    } else if cfg!(target_os = "windows") {
        let _ = Command::new("netsh").args(["interface", "ipv4", "set", "interface", interface, "forwarding=enabled"]).output();
    }
}
