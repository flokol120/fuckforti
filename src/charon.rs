//! A private strongSwan charon instance, driven over VICI.
//!
//! The instance installs no routes, policies only match traffic on our XFRM
//! interface (if_id), and DNS servers from mode-config are handed to
//! systemd-resolved for that interface via the resolve plugin.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::vici::{Msg, Session};

const CHARON: &str = "/usr/lib/strongswan/charon";
const CONN: &str = "forti";
const PSK_ID: &str = "fuckforti-psk";
const EAP_ID: &str = "fuckforti-eap";

const PLUGINS: &str = "random nonce openssl pem pkcs1 pkcs8 x509 revocation constraints pubkey kdf \
kernel-netlink socket-default vici resolve eap-identity eap-mschapv2 eap-gtc eap-md5";

fn cerr<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Charon(msg.into()))
}

pub fn strongswan_conf(cfg: &Config, rundir: &Path, debug: bool) -> String {
    let lvl = if debug { 2 } else { 1 };
    let enc = if debug { 1 } else { 0 };
    let rundir = rundir.display();
    let ifname = &cfg.ifname;
    format!(
        r#"
charon {{
    load = {PLUGINS}
    install_routes = no
    install_virtual_ip = no
    retransmit_tries = 3
    plugins {{
        vici {{
            socket = unix://{rundir}/charon.vici
        }}
        resolve {{
            resolvconf {{
                iface = {ifname}
            }}
        }}
    }}
    filelog {{
        ofi {{
            path = {rundir}/charon.log
            time_format = %H:%M:%S
            default = 1
            ike = {lvl}
            cfg = {lvl}
            enc = {enc}
            flush_line = yes
        }}
    }}
    syslog {{
        daemon {{
            default = -1
        }}
    }}
}}
"#
    )
}

fn secs(n: u64) -> String {
    format!("{n}s")
}

pub fn connection(cfg: &Config, eap_id: &str) -> Msg {
    let if_id = format!("{:#x}", cfg.if_id);
    let child = Msg::new()
        .list("local_ts", ["dynamic"])
        .list("remote_ts", ["0.0.0.0/0"])
        .list("esp_proposals", &cfg.esp_proposals)
        .kv("rekey_time", secs(cfg.child_lifetime * 9 / 10))
        .kv("life_time", secs(cfg.child_lifetime))
        .kv("if_id_in", &if_id)
        .kv("if_id_out", &if_id)
        .kv("dpd_action", "clear")
        .kv("close_action", "none")
        .kv("start_action", "none");
    let conn = Msg::new()
        .kv("version", "2")
        .list("remote_addrs", [&cfg.gateway])
        .kv("remote_port", cfg.ike_port.to_string())
        .list("proposals", &cfg.ike_proposals)
        .list("vips", ["0.0.0.0"])
        .kv("encap", "no")
        .kv("fragmentation", "yes")
        .kv("mobike", "no")
        .kv("send_certreq", "no")
        .kv("unique", "never")
        .kv("dpd_delay", secs(cfg.dpd_delay))
        .kv("rekey_time", secs(cfg.ike_lifetime * 9 / 10))
        .kv("over_time", secs(cfg.ike_lifetime / 10))
        .kv("reauth_time", "0")
        .sec("local", Msg::new().kv("auth", "eap").kv("id", &cfg.local_id).kv("eap_id", eap_id))
        .sec("remote", Msg::new().kv("auth", "psk"))
        .sec("children", Msg::new().sec(CONN, child));
    Msg::new().sec(CONN, conn)
}

pub struct Charon<'a> {
    cfg: &'a Config,
    debug: bool,
    child: Option<Child>,
    stop: Arc<AtomicBool>,
    sock_path: PathBuf,
    conf_path: PathBuf,
    pub log_path: PathBuf,
}

impl<'a> Charon<'a> {
    pub fn new(cfg: &'a Config, rundir: &Path, debug: bool, stop: Arc<AtomicBool>) -> Self {
        Charon {
            cfg,
            debug,
            child: None,
            stop,
            sock_path: rundir.join("charon.vici"),
            conf_path: rundir.join("strongswan.conf"),
            log_path: rundir.join("charon.log"),
        }
    }

    pub fn started(&self) -> bool {
        self.child.is_some()
    }

    // -- process -----------------------------------------------------------

    pub fn start(&mut self) -> Result<()> {
        if Path::new("/run/charon.pid").exists() || Path::new("/var/run/charon.vici").exists() {
            return cerr(
                "another charon is running (strongswan.service?). Stop it first: sudo systemctl stop strongswan",
            );
        }
        let rundir = self.conf_path.parent().unwrap();
        fs::write(&self.conf_path, strongswan_conf(self.cfg, rundir, self.debug))
            .or_else(|e| cerr(format!("cannot write {}: {e}", self.conf_path.display())))?;
        let mut cmd = Command::new(CHARON);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("STRONGSWAN_CONF", &self.conf_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Own session: keeps Ctrl-C on the terminal from hitting charon directly.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd.spawn().or_else(|e| cerr(format!("cannot start {CHARON}: {e}")))?;
        let child = self.child.insert(child);
        for _ in 0..100 {
            if let Ok(Some(st)) = child.try_wait() {
                return cerr(format!("charon exited with {st}; see {}", self.log_path.display()));
            }
            if self.sock_path.exists() {
                return Ok(());
            }
            sleep(Duration::from_millis(100));
        }
        cerr("charon did not create its VICI socket in time")
    }

    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else { return };
        if let Ok(None) = child.try_wait() {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    fn exited(&mut self) -> bool {
        self.child.as_mut().is_some_and(|c| !matches!(c.try_wait(), Ok(None)))
    }

    /// A VICI session; `interruptible` sessions abort when a signal arrives.
    fn session(&self, interruptible: bool) -> Result<Session> {
        Session::connect(&self.sock_path, interruptible.then(|| self.stop.clone()))
    }

    // -- operations --------------------------------------------------------

    pub fn load(&self, uid: &str, token: &str) -> Result<()> {
        let mut s = self.session(true)?;
        let ctx = |what: &'static str| move |e: Error| match e {
            Error::Charon(m) => Error::Charon(format!("{what}: {m}")),
            e => e,
        };
        s.request(
            "load-shared",
            &Msg::new().kv("id", PSK_ID).kv("type", "IKE").kv("data", &self.cfg.psk).list("owners", Vec::<&str>::new()),
        )
        .map_err(ctx("loading PSK"))?;
        s.request("load-shared", &Msg::new().kv("id", EAP_ID).kv("type", "EAP").kv("data", token).list("owners", [uid]))
            .map_err(ctx("loading EAP secret"))?;
        s.request("load-conn", &connection(self.cfg, uid)).map_err(ctx("loading connection"))?;
        Ok(())
    }

    pub fn initiate(&self, log: impl Fn(&str)) -> Result<()> {
        let mut s = self.session(true)?;
        let req = Msg::new().kv("child", CONN).kv("ike", CONN).kv("timeout", "60000").kv("init-limits", "no");
        s.streamed("initiate", "control-log", &req, |m| {
            if self.debug {
                log(&String::from_utf8_lossy(m.str("msg").unwrap_or_default()));
            }
        })
        .map(|_| ())
        .map_err(|e| match e {
            Error::Charon(m) => Error::Charon(format!("IKE negotiation failed: {m}")),
            e => e,
        })
    }

    fn sa_info(&self, interruptible: bool) -> Result<Option<Msg>> {
        let mut s = self.session(interruptible)?;
        let mut found = None;
        s.streamed("list-sas", "list-sa", &Msg::new().kv("ike", CONN), |m| {
            if let Some(sa) = m.section(CONN) {
                found.get_or_insert_with(|| sa.clone());
            }
        })?;
        Ok(found)
    }

    pub fn virtual_ip(&self) -> Result<String> {
        let Some(sa) = self.sa_info(true)? else {
            return cerr("IKE SA vanished after initiation");
        };
        sa.list_of("local-vips")
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .find(|v| !v.contains(':'))
            .map_or_else(|| cerr("gateway assigned no IPv4 virtual IP (mode config)"), Ok)
    }

    /// Best effort: close the IKE SA (sends a DELETE to the gateway).
    pub fn terminate(&self) {
        if let Ok(mut s) = self.session(false) {
            let _ = s.streamed("terminate", "control-log", &Msg::new().kv("ike", CONN).kv("timeout", "5000"), |_| {});
        }
    }

    /// Best effort: drop the PSK and the EAP token from charon's memory.
    pub fn unload_secrets(&self) {
        if let Ok(mut s) = self.session(false) {
            for id in [EAP_ID, PSK_ID] {
                let _ = s.request("unload-shared", &Msg::new().kv("id", id));
            }
        }
    }

    /// Block until the IKE SA goes down. Returns a reason, or `Error::Interrupted`.
    pub fn wait_down(&mut self) -> Result<String> {
        let mut s = self.session(true)?;
        s.register("ike-updown")?;
        loop {
            let ev = match s.next_event(Duration::from_secs(1)) {
                Ok(ev) => ev,
                Err(Error::Interrupted) => return Err(Error::Interrupted),
                Err(_) if self.exited() => return Ok("charon exited".into()),
                Err(e) => return Err(e),
            };
            if self.exited() {
                return Ok("charon exited".into());
            }
            match ev {
                // periodic check, in case an event was missed
                None => {
                    if self.sa_info(true)?.is_none() {
                        return Ok("IKE SA is gone".into());
                    }
                }
                Some((_, m)) => {
                    if m.section(CONN).is_some() && m.str("up") != Some(b"yes") {
                        return Ok("gateway closed the tunnel (IKE SA down)".into());
                    }
                }
            }
        }
    }

    pub fn tail_log(&self, n: usize) -> String {
        let Ok(data) = fs::read(&self.log_path) else { return String::new() };
        let text = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }
}

impl Drop for Charon<'_> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::base;

    #[test]
    fn conn() {
        let c = base();
        let m = connection(&c, "UID");
        let conn = m.section("forti").unwrap();
        assert_eq!(conn.str("remote_port"), Some(&b"4500"[..]));
        let local = conn.section("local").unwrap();
        assert_eq!(*local, Msg::new().kv("auth", "eap").kv("id", "ID").kv("eap_id", "UID"));
        let child = conn.section("children").unwrap().section("forti").unwrap();
        assert_eq!(child.str("if_id_in"), Some(&b"0x4f46"[..]));
        assert_eq!(child.str("life_time"), Some(&b"3600s"[..]));
        assert_eq!(conn.str("rekey_time"), Some(&b"77760s"[..]));
    }

    #[test]
    fn conf_has_no_secret() {
        let c = base();
        let conf = strongswan_conf(&c, Path::new("/run/x"), false);
        assert!(conf.contains("socket = unix:///run/x/charon.vici"));
        assert!(!conf.split_whitespace().any(|t| t == "k"));
    }
}
