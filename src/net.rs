//! Tunnel interface, routes and DNS (iproute2 + systemd-resolved).

use std::net::{IpAddr, ToSocketAddrs};
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

/// Owns everything we add to the system; `teardown()` (or drop) removes it all.
pub struct Tunnel<'a> {
    cfg: &'a Config,
    gw: String,
    host_route: Option<String>,
    created: bool,
}

impl<'a> Tunnel<'a> {
    pub fn new(cfg: &'a Config, gateway_ip: &str) -> Self {
        Tunnel { cfg, gw: gateway_ip.to_string(), host_route: None, created: false }
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

    pub fn dns_servers(&self) -> Vec<String> {
        let out = run(&["resolvectl", "dns", &self.cfg.ifname], false).map(|o| o.stdout).unwrap_or_default();
        match out.split_once(':') {
            Some((_, rest)) => rest.split_whitespace().map(String::from).collect(),
            None => Vec::new(),
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
}
