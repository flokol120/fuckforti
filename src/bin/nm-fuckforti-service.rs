//! NetworkManager VPN service for fuckforti.
//!
//! NetworkManager starts this program (see nm/nm-fuckforti-service.name) and drives
//! it over D-Bus (org.freedesktop.NetworkManager.VPN.Plugin). The connection's
//! `vpn.data` holds the same keys as config.toml; `vpn.secrets` holds `psk`.
//!
//! The service does the SAML login (opening the browser in the active desktop
//! session), runs the private charon and creates the XFRM interface. Addresses,
//! routes and DNS are then applied by NetworkManager from the Ip4Config signal.
//!
//! With `vpn.persistent yes` a dropped tunnel is brought back while NetworkManager
//! keeps the VPN active: first without, then with a new browser login.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zbus::blocking::{connection, Connection};
use zbus::interface;
use zbus::zvariant::{OwnedValue, Value};

use fuckforti::charon::Charon;
use fuckforti::config::{self, parse_v4_net, Config};
use fuckforti::error::{Error, Result};
use fuckforti::net::{self, Tunnel};
use fuckforti::{lock_rundir, monitor, saml, shutdown, Retry, Watch, RUNDIR};

const BUS_NAME: &str = "org.freedesktop.NetworkManager.fuckforti";
const PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
const IFACE: &str = "org.freedesktop.NetworkManager.VPN.Plugin";

/// How long the browser login may take. Keep below the profile's vpn.timeout.
const SAML_TIMEOUT: Duration = Duration::from_secs(280);
/// Quit when NetworkManager starts us but never sends Connect.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// NMVpnServiceState
const STATE_STARTING: u32 = 3;
const STATE_STARTED: u32 = 4;
const STATE_STOPPING: u32 = 5;
const STATE_STOPPED: u32 = 6;
// NMVpnPluginFailure
const FAILURE_LOGIN: u32 = 0;
const FAILURE_CONNECT: u32 = 1;
const FAILURE_BAD_IP_CONFIG: u32 = 2;

type Settings = HashMap<String, HashMap<String, OwnedValue>>;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.VPN.Error")]
enum VpnError {
    #[zbus(error)]
    ZBus(zbus::Error),
    BadArguments(String),
    AlreadyStarted(String),
}

/// State shared between the D-Bus handlers, the worker thread and main.
struct Shared {
    conn: OnceLock<Connection>,
    state: AtomicU32,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Gateway and virtual IP last reported to NetworkManager.
    vip: Mutex<Option<(Ipv4Addr, Ipv4Addr)>>,
}

impl Shared {
    fn emit<B>(&self, signal: &str, body: &B)
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        if let Some(c) = self.conn.get() {
            if let Err(e) = c.emit_signal(None::<&str>, PATH, IFACE, signal, body) {
                eprintln!("cannot emit {signal}: {e}");
            }
        }
    }

    fn set_state(&self, state: u32) {
        self.state.store(state, Ordering::SeqCst);
        self.emit("StateChanged", &(state,));
    }
}

fn ip_u32(ip: Ipv4Addr) -> u32 {
    // NetworkManager wants IPv4 addresses as u32 in network byte order.
    u32::from_ne_bytes(ip.octets())
}

/// The `Config` signal: generic tunnel settings.
fn nm_config(cfg: &Config, gateway: Ipv4Addr) -> HashMap<&'static str, Value<'static>> {
    HashMap::from([
        ("tundev", Value::from(cfg.ifname.clone())),
        ("gateway", Value::from(ip_u32(gateway))),
        ("mtu", Value::from(cfg.mtu)),
        ("has-ip4", Value::from(true)),
        ("has-ip6", Value::from(false)),
    ])
}

/// The `Ip4Config` signal: address, routes and DNS that NetworkManager applies.
fn nm_ip4_config(cfg: &Config, gateway: Ipv4Addr, vip: Ipv4Addr, dns: &[Ipv4Addr]) -> HashMap<&'static str, Value<'static>> {
    // [dest, prefix, next hop, metric]; next hop 0 = on-link via the tunnel device.
    let routes: Vec<Vec<u32>> = cfg
        .split_routes
        .iter()
        .filter_map(|r| parse_v4_net(r).ok())
        .map(|(net, len)| vec![ip_u32(net), u32::from(len), 0, 0])
        .collect();
    let domains: Vec<String> = cfg.dns_domains.iter().map(|d| d.trim_start_matches('~').to_string()).collect();
    let mut m = HashMap::from([
        ("gateway", Value::from(ip_u32(gateway))),
        ("address", Value::from(ip_u32(vip))),
        ("prefix", Value::from(32u32)),
        ("never-default", Value::from(!cfg.full_tunnel())),
        ("dns", Value::from(dns.iter().copied().map(ip_u32).collect::<Vec<u32>>())),
    ]);
    if !routes.is_empty() {
        m.insert("routes", Value::from(routes));
    }
    if !domains.is_empty() {
        m.insert("domains", Value::from(domains));
    }
    m
}

/// A string dictionary (a{ss}) from the "vpn" setting, e.g. `data` or `secrets`.
fn vpn_dict(settings: &Settings, key: &str) -> std::result::Result<HashMap<String, String>, VpnError> {
    let Some(v) = settings.get("vpn").and_then(|vpn| vpn.get(key)) else { return Ok(HashMap::new()) };
    let v = v.try_clone().map_err(|e| VpnError::BadArguments(e.to_string()))?;
    HashMap::<String, String>::try_from(v).map_err(|e| VpnError::BadArguments(format!("vpn.{key}: {e}")))
}

/// `vpn.persistent`: keep the VPN up across outages.
fn persistent(settings: &Settings) -> bool {
    settings
        .get("vpn")
        .and_then(|v| v.get("persistent"))
        .and_then(|v| bool::try_from(v.try_clone().ok()?).ok())
        .unwrap_or(false)
}

fn connection_id(settings: &Settings) -> String {
    settings
        .get("connection")
        .and_then(|c| c.get("id"))
        .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
        .unwrap_or_default()
}

/// Bring the tunnel up, report it to NetworkManager, and block until it goes down.
/// Sets `up` once NetworkManager got the configuration. On a reconnect the
/// interface (`tunnel`) is still there and is reused.
fn bring_up<'a>(
    sh: &Shared,
    cfg: &'a Config,
    charon: &mut Charon<'a>,
    tunnel: &mut Option<Tunnel<'a>>,
    up: &mut bool,
) -> Result<String> {
    let interrupted = || if sh.stop.load(Ordering::SeqCst) { Err(Error::Interrupted) } else { Ok(()) };
    if tunnel.is_none() && net::link_exists(&cfg.ifname) {
        return Err(Error::Net(format!("interface {} already exists: is another session running?", cfg.ifname)));
    }
    let gw_ip = net::resolve_gateway(&cfg.gateway)?;
    let gateway: Ipv4Addr = gw_ip.parse().map_err(|_| Error::Net(format!("bad gateway address {gw_ip}")))?;
    println!("Gateway {} ({gw_ip})", cfg.gateway);

    let res = saml::login(
        &cfg.gateway,
        cfg.saml_port,
        cfg.redirect_port,
        cfg.verify_tls,
        SAML_TIMEOUT,
        Some(&saml::open_browser_in_session),
        &sh.stop,
    )?;
    match &res.username {
        Some(u) => println!("SAML login ok as {u}"),
        None => println!("SAML login ok"),
    }
    interrupted()?;

    if tunnel.is_none() {
        tunnel.insert(Tunnel::new(cfg, &gw_ip)).create_link()?;
    }
    charon.start()?;
    charon.load(&res.uid, &res.token)?;
    println!("Negotiating IKEv2 with {}:{} ...", cfg.gateway, cfg.ike_port);
    charon.initiate(|m| println!("{m}"))?;
    let vip = charon.virtual_ip()?;
    let vip: Ipv4Addr = vip.parse().map_err(|_| Error::Charon(format!("bad virtual IP {vip}")))?;
    let dns = charon.dns_servers();
    interrupted()?;

    sh.emit("Config", &(nm_config(cfg, gateway),));
    sh.emit("Ip4Config", &(nm_ip4_config(cfg, gateway, vip, &dns),));
    sh.set_state(STATE_STARTED);
    *up = true;
    *sh.vip.lock().unwrap() = Some((gateway, vip));
    let shown: Vec<String> = dns.iter().map(ToString::to_string).collect();
    println!("Tunnel up: {} {vip}, dns: {}", cfg.ifname, if shown.is_empty() { "(none)".into() } else { shown.join(", ") });
    monitor(charon, |w| {
        if let Watch::Restored { vip, dns } = w {
            let vip: Ipv4Addr = vip.parse().map_err(|_| Error::Charon(format!("bad virtual IP {vip}")))?;
            sh.emit("Ip4Config", &(nm_ip4_config(cfg, gateway, vip, &dns),));
            *sh.vip.lock().unwrap() = Some((gateway, vip));
        }
        Ok(())
    })
}

/// While a full tunnel is being re-established, the default route and DNS
/// point into a tunnel without SA, so the browser could not reach the identity
/// provider. Hand NetworkManager a config without them until the tunnel is back.
fn degrade(sh: &Shared, cfg: &Config) {
    let Some((gateway, vip)) = *sh.vip.lock().unwrap() else { return };
    if !cfg.full_tunnel() {
        return; // keep company routes in the dead tunnel rather than leaking them
    }
    let mut m = nm_ip4_config(cfg, gateway, vip, &[]);
    m.insert("never-default", Value::from(true));
    m.remove("domains");
    sh.emit("Ip4Config", &(m,));
}

/// The whole session on the worker thread: connect, wait, clean up.
fn session(sh: Arc<Shared>, cfg: Config, persistent: bool) {
    let rundir = Path::new(RUNDIR);
    let lock = lock_rundir(rundir);
    let mut charon = Charon::new(&cfg, false, sh.stop.clone());
    let mut tunnel: Option<Tunnel> = None;
    let mut was_up = false;
    let mut retry = Retry::new();
    let result = match &lock {
        Ok(_) => {
            charon.remove_files(); // left over from a crashed session
            loop {
                let mut up = false;
                let res = bring_up(&sh, &cfg, &mut charon, &mut tunnel, &mut up);
                if up {
                    was_up = true;
                    retry.reset();
                }
                // Reconnect a dropped tunnel, or retry while the network is unreachable;
                // not a failed or abandoned login.
                let again = match &res {
                    Ok(reason) => {
                        println!("Tunnel lost: {reason}");
                        true
                    }
                    Err(e @ Error::Net(_)) => {
                        println!("error: {e}");
                        true
                    }
                    Err(_) => false,
                };
                if !(again && was_up && persistent) {
                    break res;
                }
                // Restart charon for a fresh login, but keep the interface:
                // NetworkManager tracks the VPN by it.
                shutdown(&mut charon, None);
                degrade(&sh, &cfg);
                match retry.wait(&sh.stop) {
                    Ok(true) => {}
                    Ok(false) => break res,
                    Err(e) => break Err(e),
                }
            }
        }
        Err(e) => Err(Error::Net(e.clone())),
    };
    let failure = match result {
        Err(Error::Interrupted) => None,
        Ok(reason) => {
            println!("Disconnected: {reason}");
            Some(FAILURE_CONNECT)
        }
        Err(e) => {
            println!("error: {e}");
            if matches!(e, Error::Charon(_)) {
                let tail = charon.tail_log(25);
                if !tail.is_empty() {
                    println!("---- charon log (tail) ----\n{tail}");
                }
            }
            Some(match e {
                Error::Saml(_) => FAILURE_LOGIN,
                Error::Charon(m) if m.contains("virtual IP") => FAILURE_BAD_IP_CONFIG,
                _ => FAILURE_CONNECT,
            })
        }
    };
    if let Some(f) = failure {
        sh.emit("Failure", &(f,));
    }
    sh.set_state(STATE_STOPPING);
    shutdown(&mut charon, tunnel.as_mut());
    if lock.is_ok() {
        charon.remove_files();
        let _ = std::fs::remove_dir_all(rundir);
    }
    sh.set_state(STATE_STOPPED);
}

struct Plugin {
    sh: Arc<Shared>,
}

impl Plugin {
    fn start(&self, settings: &Settings) -> std::result::Result<(), VpnError> {
        let mut worker = self.sh.worker.lock().unwrap();
        if worker.is_some() {
            return Err(VpnError::AlreadyStarted("a connection is already active".into()));
        }
        let data = vpn_dict(settings, "data")?;
        let secrets = vpn_dict(settings, "secrets")?;
        let cfg = config::from_nm(&data, &secrets).map_err(|e| VpnError::BadArguments(e.to_string()))?;
        let persistent = persistent(settings);
        println!("Connecting {:?}{}", connection_id(settings), if persistent { " (persistent)" } else { "" });
        self.sh.set_state(STATE_STARTING);
        let sh = self.sh.clone();
        *worker = Some(thread::spawn(move || session(sh, cfg, persistent)));
        Ok(())
    }
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl Plugin {
    fn connect(&self, connection: Settings) -> std::result::Result<(), VpnError> {
        self.start(&connection)
    }

    fn connect_interactive(
        &self,
        connection: Settings,
        _details: HashMap<String, OwnedValue>,
    ) -> std::result::Result<(), VpnError> {
        self.start(&connection)
    }

    /// The only secret is the PSK; the SAML token is obtained during Connect.
    fn need_secrets(&self, settings: Settings) -> std::result::Result<String, VpnError> {
        let secrets = vpn_dict(&settings, "secrets")?;
        Ok(if secrets.get("psk").is_some_and(|p| !p.trim().is_empty()) { String::new() } else { "vpn".into() })
    }

    fn disconnect(&self) {
        self.sh.stop.store(true, Ordering::SeqCst);
    }

    fn new_secrets(&self, _connection: Settings) {}

    // Used by helper-script based plugins; this service reports its own config.
    fn set_config(&self, _config: HashMap<String, OwnedValue>) {}
    fn set_ip4_config(&self, _config: HashMap<String, OwnedValue>) {}
    fn set_ip6_config(&self, _config: HashMap<String, OwnedValue>) {}
    fn set_failure(&self, _reason: String) {}

    #[zbus(property)]
    fn state(&self) -> u32 {
        self.sh.state.load(Ordering::SeqCst)
    }
}

fn main() -> ExitCode {
    // NetworkManager starts us with a minimal environment; ip, loginctl, systemd-run... need PATH.
    std::env::set_var("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("nm-fuckforti-service is started by NetworkManager and must run as root");
        return ExitCode::from(2);
    }

    let sh = Arc::new(Shared {
        conn: OnceLock::new(),
        state: AtomicU32::new(STATE_STOPPED),
        stop: Arc::new(AtomicBool::new(false)),
        worker: Mutex::new(None),
        vip: Mutex::new(None),
    });
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
        signal_hook::flag::register(sig, sh.stop.clone()).expect("installing signal handler");
    }

    let conn = match connection::Builder::system()
        .and_then(|b| b.name(BUS_NAME))
        .and_then(|b| b.serve_at(PATH, Plugin { sh: sh.clone() }))
        .and_then(|b| b.build())
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot register {BUS_NAME} on the system bus: {e}");
            return ExitCode::from(1);
        }
    };
    let _ = sh.conn.set(conn);

    // Serve until the session (if any) has finished, then exit: NetworkManager
    // starts a fresh service process for every connection attempt.
    let started = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(200));
        let mut worker = sh.worker.lock().unwrap();
        match worker.as_ref() {
            Some(h) if h.is_finished() => {
                let _ = worker.take().map(JoinHandle::join);
                break;
            }
            Some(_) => {}
            None if sh.stop.load(Ordering::SeqCst) || started.elapsed() > IDLE_TIMEOUT => break,
            None => {}
        }
    }
    // Give the bus a moment to deliver the final StateChanged signal.
    thread::sleep(Duration::from_millis(300));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(routes: &[&str]) -> Config {
        let data: HashMap<String, String> = [
            ("gateway", "vpn.example.com"),
            ("local_id", "ID"),
            ("split_routes", &routes.join(" ")),
            ("dns_domains", "~corp.example"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        config::from_nm(&data, &HashMap::from([("psk".into(), "k".into())])).unwrap()
    }

    #[test]
    fn network_byte_order() {
        assert_eq!(ip_u32(Ipv4Addr::new(10, 0, 0, 1)).to_ne_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn ip4_config_split() {
        let c = cfg(&["10.0.0.0/8"]);
        let m = nm_ip4_config(&c, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(10, 8, 30, 13), &[Ipv4Addr::new(10, 10, 0, 1)]);
        assert_eq!(m["never-default"], Value::from(true));
        assert_eq!(m["address"], Value::from(ip_u32(Ipv4Addr::new(10, 8, 30, 13))));
        assert_eq!(m["routes"], Value::from(vec![vec![ip_u32(Ipv4Addr::new(10, 0, 0, 0)), 8u32, 0, 0]]));
        assert_eq!(m["dns"], Value::from(vec![ip_u32(Ipv4Addr::new(10, 10, 0, 1))]));
        assert_eq!(m["domains"], Value::from(vec!["corp.example".to_string()]));
        assert_eq!(m["routes"].value_signature(), "aau");
    }

    #[test]
    fn ip4_config_full() {
        let c = cfg(&[]);
        let m = nm_ip4_config(&c, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(10, 8, 30, 13), &[]);
        assert_eq!(m["never-default"], Value::from(false));
        assert!(!m.contains_key("routes"));
    }
}
