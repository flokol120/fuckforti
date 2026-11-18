//! fuckforti: FortiGate IKEv2 + SAML VPN client for Linux (strongSwan backend).
//!
//! Shared by the `fuckforti` CLI and the `nm-fuckforti-service` NetworkManager plugin.

pub mod charon;
pub mod config;
pub mod error;
pub mod net;
pub mod saml;
pub mod vici;

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use charon::Charon;
use error::{Error, Result};
use net::Tunnel;

/// Runtime directory of a session (charon config, VICI socket, log, lock).
pub const RUNDIR: &str = "/run/fuckforti";

/// Create the run directory and take an exclusive lock on it for this process.
pub fn lock_rundir(rundir: &Path) -> std::result::Result<fs::File, String> {
    let shown = rundir.display();
    match fs::DirBuilder::new().mode(0o700).create(rundir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // A live charon socket means another session (possibly an older version) owns it.
            if std::os::unix::net::UnixStream::connect(rundir.join("charon.vici")).is_ok() {
                return Err(format!("another session is running ({shown}/charon.vici is live)"));
            }
        }
        Err(e) => return Err(format!("cannot create {shown}: {e}")),
    }
    let f = fs::File::create(rundir.join("lock")).map_err(|e| format!("cannot create {shown}/lock: {e}"))?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another fuckforti session is running".into());
    }
    Ok(f)
}

/// Tear a session down, in order: close the SA and wipe secrets, remove the
/// tunnel interface (and routes/DNS), stop charon.
pub fn shutdown(charon: &mut Charon, tunnel: Option<&mut Tunnel>) {
    if charon.started() {
        charon.terminate();
        charon.unload_secrets();
    }
    if let Some(t) = tunnel {
        t.teardown();
    }
    charon.stop();
}

/// What `monitor` reports to its caller.
pub enum Watch<'s> {
    /// About once per second while the tunnel is up.
    Tick,
    /// The IKE SA was re-established without a new login.
    Restored { vip: &'s str, dns: Vec<Ipv4Addr> },
}

/// Block while the tunnel is up. When the IKE SA drops (DPD or retransmits
/// gave up), first try to bring it back with the credentials charon still
/// holds. Returns why the tunnel is gone for good.
pub fn monitor(charon: &mut Charon, mut on: impl FnMut(Watch) -> Result<()>) -> Result<String> {
    loop {
        let reason = charon.wait_down(|| {
            let _ = on(Watch::Tick);
        })?;
        if !charon.running() {
            return Ok(reason);
        }
        println!("Tunnel lost ({reason}); re-establishing the IKE SA without a new login ...");
        on(Watch::Tick)?;
        match charon.reinitiate() {
            Ok(vip) => {
                println!("IKE SA re-established ({vip})");
                on(Watch::Restored { vip: &vip, dns: charon.dns_servers() })?;
            }
            Err(Error::Interrupted) => return Err(Error::Interrupted),
            Err(e) => return Ok(format!("{reason}; re-establishing failed: {e}")),
        }
    }
}

/// Backoff between reconnect attempts that failed because the network or the
/// gateway is unreachable (e.g. right after resume, or while offline).
pub struct Retry {
    failing_since: Option<Instant>,
    delay: Duration,
}

impl Retry {
    const FIRST: Duration = Duration::from_secs(2);
    const MAX: Duration = Duration::from_secs(60);
    /// Give up after failing this long in a row.
    const GIVE_UP: Duration = Duration::from_secs(15 * 60);

    pub fn new() -> Self {
        Retry { failing_since: None, delay: Self::FIRST }
    }

    /// The tunnel came up: start over.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Wait before the next attempt. `Ok(false)`: give up.
    pub fn wait(&mut self, stop: &AtomicBool) -> Result<bool> {
        let since = *self.failing_since.get_or_insert_with(Instant::now);
        if since.elapsed() >= Self::GIVE_UP {
            return Ok(false);
        }
        println!("Reconnecting in {}s ...", self.delay.as_secs());
        let until = Instant::now() + self.delay;
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                return Err(Error::Interrupted);
            }
            sleep(Duration::from_millis(200));
        }
        self.delay = (self.delay * 2).min(Self::MAX);
        Ok(true)
    }
}

impl Default for Retry {
    fn default() -> Self {
        Self::new()
    }
}
