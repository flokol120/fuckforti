//! fuckforti: FortiGate IKEv2 + SAML VPN client for Linux (strongSwan backend).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fuckforti::charon::Charon;
use fuckforti::config::{self, Config};
use fuckforti::error::{Error, Result};
use fuckforti::net::{self, Tunnel};
use fuckforti::{lock_rundir, monitor, saml, shutdown, Retry, Watch, RUNDIR};

const KEPT_LOG: &str = "/tmp/fuckforti-charon.log";

const USAGE: &str = "\
usage: fuckforti [-c CONFIG] [-v] [--no-browser] [--no-reconnect] [--saml-timeout SECS]

FortiGate IKEv2 + SAML VPN client for Linux (strongSwan backend).

options:
  -c, --config PATH       config file (default: /etc/fuckforti/config.toml)
  -v, --verbose           verbose IKE logging
      --no-browser        only print the SAML login URL
      --no-reconnect      exit when the tunnel drops instead of logging in again
      --saml-timeout SECS seconds to wait for the browser login (default: 300)
  -h, --help              show this help";

struct Args {
    config: PathBuf,
    verbose: bool,
    no_browser: bool,
    reconnect: bool,
    saml_timeout: u64,
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut a = Args {
        config: "/etc/fuckforti/config.toml".into(),
        verbose: false,
        no_browser: false,
        reconnect: true,
        saml_timeout: 300,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| inline.clone().or_else(|| it.next()).ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "-c" | "--config" => a.config = value(&flag)?.into(),
            "-v" | "--verbose" => a.verbose = true,
            "--no-browser" => a.no_browser = true,
            "--no-reconnect" => a.reconnect = false,
            "--saml-timeout" => {
                a.saml_timeout = value(&flag)?.parse().map_err(|_| "--saml-timeout needs a number of seconds")?
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(a)
}

fn interrupted(stop: &AtomicBool) -> Result<()> {
    if stop.load(Ordering::SeqCst) {
        Err(Error::Interrupted)
    } else {
        Ok(())
    }
}

/// Bring the tunnel up and block until it goes down. Returns why it went down.
/// Sets `up` once the tunnel is established.
fn connect<'a>(
    cfg: &'a Config,
    args: &Args,
    stop: &AtomicBool,
    charon: &mut Charon<'a>,
    tunnel: &mut Option<Tunnel<'a>>,
    up: &mut bool,
) -> Result<String> {
    let gw_ip = net::resolve_gateway(&cfg.gateway)?;
    println!("Gateway {} ({gw_ip})", cfg.gateway);
    let res = saml::login(
        &cfg.gateway,
        cfg.saml_port,
        cfg.redirect_port,
        cfg.verify_tls,
        Duration::from_secs(args.saml_timeout),
        (!args.no_browser).then_some(&saml::open_browser as &dyn Fn(&str) -> bool),
        stop,
    )?;
    match &res.username {
        Some(u) => println!("SAML login ok as {u}"),
        None => println!("SAML login ok"),
    }
    interrupted(stop)?;

    let t = tunnel.insert(Tunnel::new(cfg, &gw_ip));
    t.create_link()?;
    charon.start()?;
    charon.load(&res.uid, &res.token)?;
    println!("Negotiating IKEv2 with {}:{} ...", cfg.gateway, cfg.ike_port);
    charon.initiate(|m| println!("{m}"))?;
    let mut vip = charon.virtual_ip()?;
    interrupted(stop)?;
    let routes = t.configure(&vip)?;
    let dns = charon.dns_servers();
    t.set_dns_servers(&dns);
    *up = true;
    println!("Tunnel up: {} {vip}", cfg.ifname);
    let note = if cfg.full_tunnel() { "  (full tunnel, local LAN excluded)" } else { "" };
    println!("  routes: {}{note}", routes.join(", "));
    let dns: Vec<String> = dns.iter().map(ToString::to_string).collect();
    println!("  dns:    {}", if dns.is_empty() { "(none pushed)".to_string() } else { dns.join(", ") });
    println!("Press Ctrl-C to disconnect.");
    monitor(charon, |w| match w {
        Watch::Tick => {
            t.refresh_host_route();
            Ok(())
        }
        Watch::Restored { vip: new, dns } => {
            if new != vip {
                println!("New virtual IP {new}");
                t.configure(new)?;
                vip = new.to_string();
            }
            t.set_dns_servers(&dns);
            Ok(())
        }
    })
}

fn run() -> u8 {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            return 2;
        }
    };
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            println!("config error: {e}");
            return 2;
        }
    };
    if unsafe { libc::geteuid() } != 0 {
        println!("fuckforti must run as root (e.g. via sudo)");
        return 2;
    }

    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
        signal_hook::flag::register(sig, stop.clone()).expect("installing signal handler");
    }

    // Refuse to run next to another session: its DNS/routes would hijack our
    // gateway lookup, and our cleanup would tear down its state.
    if net::link_exists(&cfg.ifname) {
        println!(
            "interface {} already exists: is another VPN session running? \
             (if it is stale: sudo ip link del {})",
            cfg.ifname, cfg.ifname
        );
        return 1;
    }
    let rundir = Path::new(RUNDIR);
    let _lock = match lock_rundir(rundir) {
        Ok(l) => l,
        Err(e) => {
            println!("{e}");
            return 1;
        }
    };

    let mut charon = Charon::new(&cfg, args.verbose, stop.clone());
    charon.remove_files(); // left over from a crashed session
    let mut tunnel: Option<Tunnel> = None;
    let mut ran_charon = false;
    let mut was_up = false; // reconnect only sessions that worked once
    let mut retry = Retry::new();
    let rc = loop {
        let mut up = false;
        let res = connect(&cfg, &args, &stop, &mut charon, &mut tunnel, &mut up);
        ran_charon |= charon.started();
        if up {
            was_up = true;
            retry.reset();
        }
        // Only a dropped tunnel or an unreachable network are worth another
        // login; a failed or abandoned login, or an IKE error, are not.
        let again = match res {
            Ok(reason) => {
                println!("Disconnected: {reason}");
                true
            }
            Err(Error::Interrupted) => {
                println!("\nDisconnecting ...");
                break 0;
            }
            Err(e) => {
                println!("error: {e}");
                if matches!(e, Error::Charon(_)) {
                    let tail = charon.tail_log(25);
                    if !tail.is_empty() {
                        println!("---- charon log (tail) ----\n{tail}");
                    }
                }
                matches!(e, Error::Net(_))
            }
        };
        if !(again && was_up && args.reconnect) {
            break 1;
        }
        shutdown(&mut charon, tunnel.as_mut());
        tunnel = None;
        match retry.wait(&stop) {
            Ok(true) => {}
            Ok(false) => {
                println!("Giving up: could not reconnect.");
                break 1;
            }
            Err(_) => {
                println!("\nDisconnecting ...");
                break 0;
            }
        }
    };

    shutdown(&mut charon, tunnel.as_mut());
    if args.verbose && ran_charon && fs::copy(&charon.log_path, KEPT_LOG).is_ok() {
        println!("charon log kept at {KEPT_LOG}");
    }
    charon.remove_files();
    let _ = fs::remove_dir_all(rundir);
    rc
}

fn main() -> ExitCode {
    ExitCode::from(run())
}
