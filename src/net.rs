//! Tunnel interface, routes and DNS (iproute2 + systemd-resolved).

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::process::Command;

use crate::config::Config;
use crate::error::{Error, Result};

struct Out {
    ok: bool,
    stdout: String,
}

fn run(args: &[&str], check: bool) -> Result<Out> {
    let p = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| Error::Net(format!("cannot run {}: {e}", args[0])))?;
    let stdout = String::from_utf8_lossy(&p.stdout).into_owned();
    if check && !p.status.success() {
        let stderr = String::from_utf8_lossy(&p.stderr);
        let msg = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
        return Err(Error::Net(format!("{}: {msg}", args.join(" "))));
    }
    Ok(Out { ok: p.status.success(), stdout })
}

pub fn resolve_gateway(host: &str) -> Result<String> {
    let addrs = (host, 0).to_socket_addrs().map_err(|e| Error::Net(format!("cannot resolve {host}: {e}")))?;
    addrs
        .map(|a| a.ip())
        .find(IpAddr::is_ipv4)
        .map(|ip| ip.to_string())
        .ok_or_else(|| Error::Net(format!("{host} has no IPv4 address")))
}

pub fn link_exists(name: &str) -> bool {
    run(&["ip", "link", "show", "dev", name], false).is_ok_and(|o| o.ok)
}

/// Keep only the `via X` / `dev Y` parts of `ip route get` output, e.g.
/// "1.2.3.4 via 192.168.2.1 dev enp8s0 src 192.168.2.3 uid 0" -> [via, 192.168.2.1, dev, enp8s0].
fn route_via(route_get: &str) -> Vec<String> {
    let toks: Vec<&str> = route_get.split_whitespace().collect();
    let end = toks.iter().position(|t| *t == "uid").unwrap_or(toks.len());
    let mut keep = Vec::new();
    let mut it = toks.get(1..end).unwrap_or_default().iter();
    while let Some(tok) = it.next() {
        if matches!(*tok, "via" | "dev") {
            if let Some(v) = it.next() {
                keep.push(tok.to_string());
                keep.push(v.to_string());
            }
        }
    }
    keep
}

/// The main-table route to `gw` that does not use our tunnel or our own host
/// route: longest prefix, then lowest metric. Returns its `via`/`dev` parts.
fn underlay_route(table: &str, gw: Ipv4Addr, tunnel: &str) -> Option<Vec<String>> {
    let mut best: Option<(u8, u32, Vec<String>)> = None;
    for line in table.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(dest) = toks.first() else { continue };
        let (net, len) = if *dest == "default" {
            (Ipv4Addr::UNSPECIFIED, 0)
        } else {
            let (a, l) = dest.split_once('/').unwrap_or((dest, "32"));
            match (a.parse::<Ipv4Addr>(), l.parse::<u8>()) {
                (Ok(a), Ok(l)) if l <= 32 => (a, l),
                _ => continue, // unreachable/blackhole/... routes
            }
        };
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        let dev = toks.iter().position(|t| *t == "dev").and_then(|i| toks.get(i + 1));
        if u32::from(gw) & mask != u32::from(net) & mask
            || (net == gw && len == 32)
            || !dev.is_some_and(|d| *d != tunnel)
            || toks.contains(&"linkdown")
        {
            continue;
        }
        let metric = toks.iter().position(|t| *t == "metric").and_then(|i| toks.get(i + 1)?.parse().ok()).unwrap_or(0);
        let better = match &best {
            Some((bl, bm, _)) => len > *bl || (len == *bl && metric < *bm),
            None => true,
        };
        if better {
            best = Some((len, metric, route_via(line)));
        }
    }
    best.map(|(_, _, via)| via)
}

/// Owns everything we add to the system; `teardown()` (or drop) removes it all.
pub struct Tunnel<'a> {
    cfg: &'a Config,
    gw: String,
    host_route: Option<String>,
    /// Last seen physical path to the gateway (see `refresh_host_route`).
    underlay: Option<Vec<String>>,
    created: bool,
}

impl<'a> Tunnel<'a> {
    pub fn new(cfg: &'a Config, gateway_ip: &str) -> Self {
        Tunnel { cfg, gw: gateway_ip.to_string(), host_route: None, underlay: None, created: false }
    }

    pub fn create_link(&mut self) -> Result<()> {
        let name = &self.cfg.ifname;
        if link_exists(name) {
            return Err(Error::Net(format!(
                "interface {name} already exists (stale session? `sudo ip link del {name}`)"
            )));
        }
        let if_id = format!("{:#x}", self.cfg.if_id);
        run(&["ip", "link", "add", name, "type", "xfrm", "if_id", &if_id], true)?;
        self.created = true;
        run(&["ip", "link", "set", name, "mtu", &self.cfg.mtu.to_string(), "up"], true)?;
        Ok(())
    }

    pub fn configure(&mut self, vip: &str) -> Result<Vec<String>> {
        let name = self.cfg.ifname.as_str();
        // also used after a re-established SA brought a new virtual IP
        run(&["ip", "addr", "flush", "dev", name], true)?;
        run(&["ip", "addr", "add", &format!("{vip}/32"), "dev", name], true)?;
        let routes: Vec<String> = if self.cfg.full_tunnel() {
            // Keep IKE/ESP to the gateway on the physical path, then cover all of
            // IPv4 with two /1s. More specific routes (local LAN) keep working.
            let out = run(&["ip", "-4", "route", "get", &self.gw], true)?;
            let host = format!("{}/32", self.gw);
            let mut args = vec!["ip".to_string(), "route".into(), "replace".into(), host.clone()];
            args.extend(route_via(&out.stdout));
            run(&args.iter().map(String::as_str).collect::<Vec<_>>(), true)?;
            self.host_route = Some(host);
            self.underlay = self.main_underlay();
            vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()]
        } else {
            self.cfg.split_routes.clone()
        };
        for r in &routes {
            run(&["ip", "route", "replace", r, "dev", name, "src", vip], true)?;
        }
        self.dns();
        Ok(routes)
    }

    fn main_underlay(&self) -> Option<Vec<String>> {
        let gw: Ipv4Addr = self.gw.parse().ok()?;
        let table = run(&["ip", "-4", "-o", "route", "show", "table", "main"], true).ok()?;
        underlay_route(&table.stdout, gw, &self.cfg.ifname)
    }

    /// Full tunnel: keep the host route to the gateway on the current uplink.
    /// When the uplink changes (Wi-Fi <-> Ethernet, new DHCP lease) the old
    /// route is stale or gone; MOBIKE then moves the SA once IKE can get out.
    pub fn refresh_host_route(&mut self) {
        let Some(host) = self.host_route.clone() else { return };
        let Some(now) = self.main_underlay() else { return }; // offline: keep what we have
        let present = run(&["ip", "-4", "route", "show", "exact", &host], false).is_ok_and(|o| !o.stdout.trim().is_empty());
        if present && self.underlay.as_ref() == Some(&now) {
            return;
        }
        let mut args = vec!["ip", "route", "replace", host.as_str()];
        args.extend(now.iter().map(String::as_str));
        if run(&args, true).is_ok() {
            println!("Gateway route now {}", now.join(" "));
            self.underlay = Some(now);
        }
    }

    fn dns(&self) {
        let name = self.cfg.ifname.as_str();
        let mut domains: Vec<String> = self
            .cfg
            .dns_domains
            .iter()
            .map(|d| if d.starts_with('~') { d.clone() } else { format!("~{d}") })
            .collect();
        let default_route = if self.cfg.full_tunnel() {
            domains.push("~.".into());
            "yes"
        } else {
            "no"
        };
        let _ = run(&["resolvectl", "default-route", name, default_route], false);
        if !domains.is_empty() {
            let mut args = vec!["resolvectl", "domain", name];
            args.extend(domains.iter().map(String::as_str));
            let _ = run(&args, false);
        }
    }

    /// Hand the DNS servers pushed by the gateway to systemd-resolved for our link.
    pub fn set_dns_servers(&self, servers: &[Ipv4Addr]) {
        let servers: Vec<String> = servers.iter().map(ToString::to_string).collect();
        let mut args = vec!["resolvectl", "dns", self.cfg.ifname.as_str()];
        args.extend(servers.iter().map(String::as_str));
        if let Err(e) = run(&args, true) {
            println!("warning: cannot set DNS servers: {e}");
        }
    }

    pub fn teardown(&mut self) {
        if let Some(host) = self.host_route.take() {
            let _ = run(&["ip", "route", "del", &host], false);
        }
        if self.created {
            let name = self.cfg.ifname.as_str();
            let _ = run(&["resolvectl", "revert", name], false);
            let _ = run(&["ip", "link", "del", name], false);
            self.created = false;
        }
    }
}

impl Drop for Tunnel<'_> {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn via() {
        assert_eq!(
            route_via("1.2.3.4 via 192.168.2.1 dev enp8s0 src 192.168.2.3 uid 0 \n    cache"),
            ["via", "192.168.2.1", "dev", "enp8s0"]
        );
        assert_eq!(route_via("1.2.3.4 dev wlan0 src 10.0.0.2"), ["dev", "wlan0"]);
        assert!(route_via("").is_empty());
    }

    #[test]
    fn underlay() {
        let gw = Ipv4Addr::new(1, 2, 3, 4);
        let table = "\
default via 192.168.2.1 dev enp8s0 proto dhcp src 192.168.2.3 metric 100
default via 10.1.0.1 dev wlan0 proto dhcp src 10.1.0.5 metric 600
0.0.0.0/1 dev forti0 scope link src 10.212.0.7
128.0.0.0/1 dev forti0 scope link src 10.212.0.7
1.2.3.4 via 192.168.2.1 dev enp8s0
192.168.2.0/24 dev enp8s0 proto kernel scope link src 192.168.2.3 metric 100
unreachable 1.2.0.0/16";
        assert_eq!(underlay_route(table, gw, "forti0").unwrap(), ["via", "192.168.2.1", "dev", "enp8s0"]);
        // Ethernet unplugged: its routes are gone, Wi-Fi remains
        let wifi: String = table.lines().filter(|l| !l.contains("enp8s0")).collect::<Vec<_>>().join("\n");
        assert_eq!(underlay_route(&wifi, gw, "forti0").unwrap(), ["via", "10.1.0.1", "dev", "wlan0"]);
        // gateway in a directly connected subnet
        let lan = "default via 192.168.2.1 dev enp8s0 metric 100\n1.2.3.0/24 dev eth1 proto kernel scope link src 1.2.3.9";
        assert_eq!(underlay_route(lan, gw, "forti0").unwrap(), ["dev", "eth1"]);
        assert!(underlay_route("0.0.0.0/1 dev forti0 scope link", gw, "forti0").is_none());
    }
}
