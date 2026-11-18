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
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use charon::Charon;
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
