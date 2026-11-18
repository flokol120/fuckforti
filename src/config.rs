//! Configuration: from a TOML file (CLI) or from NetworkManager's vpn.data (service).

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub gateway: String,
    #[serde(rename = "psk")]
    psk_inline: Option<String>,
    psk_file: Option<PathBuf>,
    /// The resolved pre-shared key (from `psk` or `psk_file`).
    #[serde(skip)]
    pub psk: String,
    pub local_id: String,
    pub saml_port: u16,
    pub ike_port: u16,
    pub redirect_port: u16,
    pub verify_tls: bool,
    pub ike_proposals: Vec<String>,
    pub esp_proposals: Vec<String>,
    pub ike_lifetime: u64,
    pub child_lifetime: u64,
    pub dpd_delay: u64,
    /// IKE retransmissions before charon declares the peer dead (strongSwan
    /// timeout 4 s, factor 1.8: 5 tries = ~165 s of outage tolerated).
    pub retransmit_tries: u32,
    /// MOBIKE (RFC 4555): move the SA to a new local address instead of dropping it.
    pub mobike: bool,
    /// Always UDP-encapsulate ESP, even without NAT (for networks that drop raw ESP).
    pub force_encap: bool,
    pub ifname: String,
    pub if_id: u32,
    pub mtu: u32,
    /// Empty = full tunnel (everything except the local LAN goes through the VPN).
    pub split_routes: Vec<String>,
    /// DNS search/routing domains resolved via the VPN DNS servers.
    /// Empty and full tunnel = all DNS queries go to the VPN.
    pub dns_domains: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            gateway: String::new(),
            psk_inline: None,
            psk_file: None,
            psk: String::new(),
            local_id: String::new(),
            saml_port: 443,
            ike_port: 500,
            redirect_port: 8020,
            verify_tls: true,
            ike_proposals: vec!["aes256gcm16-prfsha384-ecp384".into()],
            esp_proposals: vec!["aes256gcm16-ecp384".into()],
            ike_lifetime: 86400,
            child_lifetime: 3600,
            dpd_delay: 20,
            retransmit_tries: 5,
            mobike: true,
            force_encap: false,
            ifname: "forti0".into(),
            if_id: 0x4F46,
            mtu: 1400,
            split_routes: Vec::new(),
            dns_domains: Vec::new(),
        }
    }
}

impl Config {
    pub fn full_tunnel(&self) -> bool {
        self.split_routes.is_empty()
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Config(msg.into()))
}

pub fn load(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
    parse(&text, path.parent().unwrap_or(Path::new(".")))
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

/// Parse TOML text; a relative `psk_file` is resolved against `base`.
pub fn parse(text: &str, base: &Path) -> Result<Config> {
    let mut cfg: Config = toml::from_str(text).map_err(|e| Error::Config(e.message().to_string()))?;
    cfg.psk = match (cfg.psk_inline.take(), cfg.psk_file.take()) {
        (Some(_), Some(_)) => return err("set either 'psk' or 'psk_file', not both"),
        (Some(psk), None) => psk,
        (None, Some(p)) => {
            let p = if p.is_absolute() { p } else { base.join(p) };
            fs::read_to_string(&p)
                .map_err(|e| Error::Config(format!("cannot read psk_file {}: {e}", p.display())))?
                .trim()
                .to_string()
        }
        (None, None) => String::new(),
    };
    validate(&cfg)?;
    Ok(cfg)
}

/// Build a config from a NetworkManager connection's `vpn.data` / `vpn.secrets`.
/// Keys are the TOML field names; list values are separated by spaces or `;`
/// (nmcli uses `,` between key=value pairs).
pub fn from_nm(data: &HashMap<String, String>, secrets: &HashMap<String, String>) -> Result<Config> {
    fn num<T: std::str::FromStr>(k: &str, v: &str) -> Result<T> {
        let v = v.strip_prefix("0x").map_or_else(|| v.parse().ok(), |hex| {
            u64::from_str_radix(hex, 16).ok().and_then(|n| n.to_string().parse().ok())
        });
        v.map_or_else(|| err(format!("vpn.data {k}: not a valid number")), Ok)
    }
    fn flag(k: &str, v: &str) -> Result<bool> {
        match v {
            "yes" | "true" | "1" => Ok(true),
            "no" | "false" | "0" => Ok(false),
            _ => err(format!("vpn.data {k}: expected yes or no")),
        }
    }
    fn list(v: &str) -> Vec<String> {
        v.split(|c: char| c.is_whitespace() || c == ';' || c == ',').filter(|s| !s.is_empty()).map(String::from).collect()
    }
    let mut cfg = Config::default();
    for (k, v) in data {
        let v = v.trim();
        match k.as_str() {
            "gateway" => cfg.gateway = v.to_string(),
            "local_id" => cfg.local_id = v.to_string(),
            "saml_port" => cfg.saml_port = num(k, v)?,
            "ike_port" => cfg.ike_port = num(k, v)?,
            "redirect_port" => cfg.redirect_port = num(k, v)?,
            "verify_tls" => cfg.verify_tls = flag(k, v)?,
            "mobike" => cfg.mobike = flag(k, v)?,
            "force_encap" => cfg.force_encap = flag(k, v)?,
            "retransmit_tries" => cfg.retransmit_tries = num(k, v)?,
            "ike_proposals" => cfg.ike_proposals = list(v),
            "esp_proposals" => cfg.esp_proposals = list(v),
            "ike_lifetime" => cfg.ike_lifetime = num(k, v)?,
            "child_lifetime" => cfg.child_lifetime = num(k, v)?,
            "dpd_delay" => cfg.dpd_delay = num(k, v)?,
            "ifname" => cfg.ifname = v.to_string(),
            "if_id" => cfg.if_id = num(k, v)?,
            "mtu" => cfg.mtu = num(k, v)?,
            "split_routes" => cfg.split_routes = list(v),
            "dns_domains" => cfg.dns_domains = list(v),
            // secret flags (e.g. psk-flags) belong to NetworkManager
            k if k.ends_with("-flags") => {}
            _ => return err(format!("unknown vpn.data key {k:?}")),
        }
    }
    cfg.psk = secrets.get("psk").map(|p| p.trim().to_string()).unwrap_or_default();
    validate(&cfg)?;
    Ok(cfg)
}

fn valid_ifname(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Parse a strict IPv4 CIDR (no host bits set).
pub fn parse_v4_net(s: &str) -> std::result::Result<(Ipv4Addr, u8), String> {
    let (addr, len) = s.split_once('/').unwrap_or((s, "32"));
    if addr.contains(':') {
        return Err("only IPv4 split routes are supported".into());
    }
    let addr: Ipv4Addr = addr.parse().map_err(|_| "not an IPv4 address".to_string())?;
    let len: u8 = len.parse().ok().filter(|l| *l <= 32).ok_or("bad prefix length")?;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    if u32::from(addr) & !mask != 0 {
        return Err("has host bits set".into());
    }
    Ok((addr, len))
}

fn validate(cfg: &Config) -> Result<()> {
    if cfg.gateway.is_empty() || cfg.gateway.contains(['/', ' ', ':']) {
        return err("'gateway' must be a bare host name or IP address");
    }
    if cfg.psk.is_empty() {
        return err("a pre-shared key is required ('psk' or 'psk_file')");
    }
    if cfg.local_id.is_empty() {
        return err("'local_id' is required (FortiClient: Phase 1 > Local ID)");
    }
    for (name, v) in [("saml_port", cfg.saml_port), ("ike_port", cfg.ike_port), ("redirect_port", cfg.redirect_port)] {
        if v == 0 {
            return err(format!("'{name}' must be a port number"));
        }
    }
    if !valid_ifname(&cfg.ifname) {
        return err("'ifname' must be a valid interface name (max 15 chars)");
    }
    for r in &cfg.split_routes {
        parse_v4_net(r).or_else(|e| err(format!("invalid split route {r:?}: {e}")))?;
    }
    for d in &cfg.dns_domains {
        let body = d.strip_prefix('~').unwrap_or(d);
        if body.is_empty() || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return err(format!("invalid DNS domain {d:?}"));
        }
    }
    if !(1..=15).contains(&cfg.retransmit_tries) {
        return err("'retransmit_tries' must be between 1 and 15");
    }
    if cfg.ike_proposals.is_empty() || cfg.esp_proposals.is_empty() {
        return err("proposal lists must not be empty");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const BASE: &str = r#"
        gateway = "vpn.example.com"
        psk = "k"
        local_id = "ID"
        saml_port = 9443
        ike_port = 4500
    "#;

    pub fn base() -> Config {
        parse(BASE, Path::new(".")).unwrap()
    }

    fn with(line: &str) -> Result<Config> {
        // Later keys can't override earlier ones in TOML, so drop the one we replace.
        let key = line.split('=').next().unwrap().trim();
        let kept: Vec<&str> = BASE.lines().filter(|l| l.split('=').next().unwrap().trim() != key).collect();
        parse(&format!("{}\n{line}\n", kept.join("\n")), Path::new("."))
    }

    #[test]
    fn defaults() {
        let c = base();
        assert!(c.full_tunnel());
        assert_eq!(c.ike_proposals, ["aes256gcm16-prfsha384-ecp384"]);
        assert_eq!(c.psk, "k");
        assert!(c.mobike && !c.force_encap);
        assert_eq!(c.retransmit_tries, 5);
    }

    #[test]
    fn rejects() {
        for bad in [
            r#"psk = """#,
            r#"gateway = "https://x""#,
            r#"split_routes = ["10.0.0.1/8"]"#,
            r#"split_routes = ["fd00::/8"]"#,
            r#"ifname = "xxxxxxxxxxxxxxxx""#,
            r#"bogus = 1"#,
            r#"saml_port = 0"#,
            r#"psk_file = "psk""#,
            r#"dns_domains = ["a b"]"#,
            r#"retransmit_tries = 0"#,
        ] {
            assert!(with(bad).is_err(), "accepted {bad}");
        }
        assert!(with(r#"split_routes = ["10.0.0.0/8"]"#).is_ok());
    }

    fn nm(pairs: &[(&str, &str)]) -> Result<Config> {
        let mut data: HashMap<String, String> =
            [("gateway", "vpn.example.com"), ("local_id", "ID"), ("psk-flags", "0")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        data.extend(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let secrets = HashMap::from([("psk".to_string(), "k".to_string())]);
        from_nm(&data, &secrets)
    }

    #[test]
    fn nm_data() {
        let c = nm(&[
            ("ike_port", "4500"),
            ("split_routes", "10.0.0.0/8 172.16.0.0/12"),
            ("dns_domains", "a.example;b.example"),
            ("if_id", "0x10"),
            ("verify_tls", "no"),
            ("mobike", "no"),
            ("retransmit_tries", "8"),
        ])
        .unwrap();
        assert_eq!(c.ike_port, 4500);
        assert_eq!(c.split_routes, ["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(c.dns_domains, ["a.example", "b.example"]);
        assert_eq!(c.if_id, 16);
        assert!(!c.verify_tls);
        assert!(!c.mobike && !c.force_encap);
        assert_eq!(c.retransmit_tries, 8);
        assert_eq!(c.psk, "k");
        assert_eq!(c.ike_proposals, Config::default().ike_proposals);

        for bad in [("bogus", "1"), ("ike_port", "x"), ("ike_port", "70000"), ("split_routes", "10.0.0.1/8"), ("verify_tls", "maybe")] {
            assert!(nm(&[bad]).is_err(), "accepted {bad:?}");
        }
        assert!(from_nm(&HashMap::from([("gateway".into(), "x".into()), ("local_id".into(), "I".into())]), &HashMap::new()).is_err());
    }

    #[test]
    fn missing_local_id() {
        let raw: String = BASE.lines().filter(|l| !l.contains("local_id")).collect::<Vec<_>>().join("\n");
        assert!(parse(&raw, Path::new(".")).is_err());
    }
}
