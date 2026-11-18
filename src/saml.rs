//! FortiGate IKEv2 SAML pre-authentication.
//!
//! Flow (as used by FortiClient):
//!   1. POST https://<gw>:<saml_port>/saml_login? with
//!      {"type":"rawData","bytes":"UID=<UID>&REDIRECT_PORT=<port>"}
//!      -> small HTML page with window.location="https://<gw>:<saml_port>/saml?<id>"
//!   2. The user logs in at that URL in a browser (IdP, MFA, ...).
//!   3. The FortiGate redirects the browser to
//!      http://127.0.0.1:<port>/?tokenid=<TOKEN>&username=<USER>
//!   4. IKEv2 EAP then uses identity=<UID>, secret=<TOKEN>.

use std::env;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

const USER_AGENT: &str = "FortiSSLVPN (Linux; SV1 [SV{v=02.01; f=05;}])";

const SUCCESS_PAGE: &str = r#"<!doctype html><html><head><meta charset="utf-8">
<title>VPN login complete</title>
<script>history.replaceState(null, "", "/"); window.close();</script></head>
<body style="font-family:sans-serif"><h2>VPN login complete</h2>
<p>You can close this tab.</p></body></html>"#;

fn serr<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Saml(msg.into()))
}

pub struct SamlResult {
    pub uid: String,
    pub token: String,
    pub username: Option<String>,
}

pub fn new_uid() -> String {
    let mut b = [0u8; 16];
    File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("reading /dev/urandom");
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Find `[window.]location[.href] = "<url>"` in the FortiGate's HTML and return the https URL.
pub fn extract_redirect(html: &str) -> Result<String> {
    let lower = html.to_ascii_lowercase(); // same byte offsets as `html`
    let b = lower.as_bytes();
    let skip_ws = |mut p: usize| {
        while p < b.len() && b[p].is_ascii_whitespace() {
            p += 1;
        }
        p
    };
    let mut from = 0;
    while let Some(i) = lower[from..].find("location") {
        let mut p = from + i + "location".len();
        from = p;
        if b[p..].starts_with(b".href") {
            p += 5;
        }
        p = skip_ws(p);
        if b.get(p) != Some(&b'=') {
            continue;
        }
        p = skip_ws(p + 1);
        if !matches!(b.get(p), Some(b'"' | b'\'')) {
            continue;
        }
        let start = p + 1;
        let Some(len) = b[start..].iter().position(|c| matches!(c, b'"' | b'\'')) else { continue };
        if len == 0 {
            continue;
        }
        let url = &html[start..start + len];
        if !url.to_ascii_lowercase().starts_with("https://") {
            return serr(format!("unexpected SAML redirect URL scheme: {url:?}"));
        }
        return Ok(url.to_string());
    }
    serr("FortiGate response contained no SAML redirect URL")
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => match s
                .get(i + 1..i + 3)
                .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                Some(v) => {
                    out.push(v);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the browser's callback path into (token, username).
pub fn parse_callback(path: &str) -> Option<(String, Option<String>)> {
    let query = path.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or("");
    let mut token = None;
    let mut user = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        if v.is_empty() {
            continue;
        }
        match percent_decode(k).as_str() {
            "tokenid" => token = token.or(Some(v)),
            "username" => user = user.or(Some(v)),
            _ => {}
        }
    }
    Some((token?, user))
}

/// Decode a `Transfer-Encoding: chunked` body.
fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&data[..eol]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        data = &data[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(data.get(..size)?);
        data = data.get(size + 2..)?;
    }
}

/// Split a raw HTTP/1.1 response into (status, body).
fn parse_response(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..hdr_end]);
    let body = &raw[hdr_end + 4..];
    let mut lines = head.lines();
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut length = None;
    let mut chunked = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            length = v.parse::<usize>().ok();
        } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else if let Some(n) = length {
        body.get(..n)?.to_vec()
    } else {
        body.to_vec()
    };
    Some((status, body))
}

/// POST the UID to /saml_login and return the browser login URL.
///
/// Hand-rolled on purpose: the FortiGate only answers `POST /saml_login?` with
/// the literal trailing `?`, which URL-normalizing HTTP clients drop.
fn request_login_url(gateway: &str, port: u16, uid: &str, redirect_port: u16, verify_tls: bool) -> Result<String> {
    let endpoint = format!("https://{gateway}:{port}");
    let fail = |what: &str, e: &dyn std::fmt::Display| Error::Saml(format!("cannot reach SAML endpoint {endpoint}: {what}: {e}"));
    let timeout = Duration::from_secs(15);

    let addr = (gateway, port)
        .to_socket_addrs()
        .map_err(|e| fail("resolve", &e))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| fail("resolve", &"no IPv4 address"))?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| fail("connect", &e))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .danger_accept_invalid_hostnames(!verify_tls)
        .build()
        .map_err(|e| fail("TLS setup", &e))?;
    let mut s = tls.connect(gateway, tcp).map_err(|e| fail("TLS handshake", &e))?;

    let body = format!(r#"{{"type": "rawData", "bytes": "UID={uid}&REDIRECT_PORT={redirect_port}"}}"#);
    let req = format!(
        "POST /saml_login? HTTP/1.1\r\nHost: {gateway}:{port}\r\nAccept: */*\r\n\
         Content-Type: application/json\r\nUser-Agent: {USER_AGENT}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| fail("send", &e))?;

    let mut raw = Vec::new();
    let mut tmp = [0u8; 8192];
    while raw.len() < 65536 {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            // FortiGates may close without TLS close_notify; keep what we got.
            Err(_) if !raw.is_empty() => break,
            Err(e) => return Err(fail("receive", &e)),
        }
    }
    if raw.is_empty() {
        return Err(fail("receive", &"gateway closed the connection without a response"));
    }
    let (status, html) = parse_response(&raw).ok_or_else(|| fail("receive", &"malformed HTTP response"))?;
    if status != 200 {
        return Err(fail("request", &format!("HTTP {status}")));
    }
    extract_redirect(&String::from_utf8_lossy(&html))
}

fn in_path(cmd: &str) -> bool {
    env::var_os("PATH")
        .is_some_and(|p| env::split_paths(&p).any(|d| d.join(cmd).is_file()))
}

/// Open URL in the invoking (non-root) user's browser when run via sudo.
pub fn open_browser(url: &str) -> bool {
    let sudo_user = env::var("SUDO_USER").ok().filter(|u| !u.is_empty());
    let as_user = sudo_user.filter(|_| unsafe { libc::geteuid() } == 0);
    open_browser_as(as_user.as_deref(), url)
}

/// Owner of the active graphical session on seat0, from logind.
fn active_session_user() -> Option<String> {
    let value = |args: &[&str]| -> Option<String> {
        let out = Command::new("loginctl").args(args).stderr(Stdio::null()).output().ok()?;
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !v.is_empty()).then_some(v)
    };
    let session = value(&["show-seat", "seat0", "--property=ActiveSession", "--value"])?;
    value(&["show-session", &session, "--property=Name", "--value"]).filter(|u| u != "root")
}

/// Open URL in the browser of whoever sits at the active graphical session.
/// For a root service (NetworkManager plugin) that has no SUDO_USER and no display.
pub fn open_browser_in_session(url: &str) -> bool {
    let Some(user) = active_session_user() else { return false };
    // The user's systemd manager has the session environment (WAYLAND_DISPLAY,
    // DISPLAY, ...) imported by the desktop, so xdg-open runs as if they ran it.
    let ok = Command::new("systemd-run")
        .args(["--user", &format!("--machine={user}@.host"), "--collect", "--quiet", "--", "xdg-open", url])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|st| st.success());
    ok || open_browser_as(Some(&user), url)
}

/// Run xdg-open, as `user` (from root) with a reconstructed session environment.
fn open_browser_as(user: Option<&str>, url: &str) -> bool {
    if !in_path("xdg-open") {
        return false;
    }
    let mut cmd = match user {
        Some(user) => {
            let Ok(cname) = CString::new(user) else { return false };
            let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
            if pw.is_null() {
                return false;
            }
            let (uid, home) = unsafe { ((*pw).pw_uid, CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned()) };
            let rundir = format!("/run/user/{uid}");
            let mut envs = vec![
                format!("HOME={home}"),
                format!("USER={user}"),
                "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
                format!("XDG_RUNTIME_DIR={rundir}"),
                format!("DBUS_SESSION_BUS_ADDRESS=unix:path={rundir}/bus"),
                format!("DISPLAY={}", env::var("DISPLAY").unwrap_or_else(|_| ":0".into())),
            ];
            let wl = env::var("WAYLAND_DISPLAY").ok().filter(|w| !w.is_empty()).or_else(|| {
                Path::new(&format!("{rundir}/wayland-0")).exists().then(|| "wayland-0".to_string())
            });
            if let Some(wl) = wl {
                envs.push(format!("WAYLAND_DISPLAY={wl}"));
            }
            let mut c = Command::new("runuser");
            c.args(["-u", user, "--", "env", "-i"]).args(&envs).args(["xdg-open", url]);
            c
        }
        None => {
            let mut c = Command::new("xdg-open");
            c.arg(url);
            c
        }
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(mut child) => {
            thread::spawn(move || child.wait());
            true
        }
        Err(_) => false,
    }
}

/// Serve one HTTP request on the callback listener. Returns the token if it was the SAML callback.
fn handle(mut s: TcpStream) -> Option<(String, Option<String>)> {
    s.set_nonblocking(false).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut req = Vec::new();
    let mut tmp = [0u8; 2048];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16384 {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => req.extend_from_slice(&tmp[..n]),
        }
    }
    let head = String::from_utf8_lossy(&req);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let parsed = match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => parse_callback(path),
        _ => None,
    };
    let resp = match parsed {
        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        Some(_) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{SUCCESS_PAGE}",
            SUCCESS_PAGE.len()
        ),
    };
    let _ = s.write_all(resp.as_bytes());
    parsed
}

pub fn login(
    gateway: &str,
    saml_port: u16,
    redirect_port: u16,
    verify_tls: bool,
    timeout: Duration,
    browser: Option<&dyn Fn(&str) -> bool>,
    stop: &AtomicBool,
) -> Result<SamlResult> {
    let listener = TcpListener::bind(("127.0.0.1", redirect_port))
        .or_else(|e| serr(format!("cannot listen on 127.0.0.1:{redirect_port}: {e}")))?;
    listener.set_nonblocking(true).or_else(|e| serr(e.to_string()))?;

    let uid = new_uid();
    let url = request_login_url(gateway, saml_port, &uid, redirect_port, verify_tls)?;
    println!("Log in to the VPN in your browser:\n  {url}");
    if browser.is_some_and(|open| !open(&url)) {
        println!("(could not open a browser automatically; open the URL above manually)");
    }

    let deadline = Instant::now() + timeout;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(Error::Interrupted);
        }
        if Instant::now() >= deadline {
            return serr(format!("no SAML login completed within {}s", timeout.as_secs()));
        }
        match listener.accept() {
            Ok((s, _)) => {
                // never log the token-bearing URL
                if let Some((token, username)) = handle(s) {
                    return Ok(SamlResult { uid, token, username });
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(100)),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return serr(format!("callback listener: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect() {
        let html = r#"<html><body><script language="JavaScript">window.location="https://gw:9443/saml?268f71afac804bdb";</script></body></html>"#;
        assert_eq!(extract_redirect(html).unwrap(), "https://gw:9443/saml?268f71afac804bdb");
        assert_eq!(extract_redirect("Location.HREF = 'https://a/b'").unwrap(), "https://a/b");
        assert!(extract_redirect(r#"window.location="javascript:alert(1)""#).is_err());
        assert!(extract_redirect("no redirect here").is_err());
    }

    #[test]
    fn callback() {
        assert_eq!(
            parse_callback("/?tokenid=ABC&username=me%40x.de"),
            Some(("ABC".into(), Some("me@x.de".into())))
        );
        assert_eq!(parse_callback("/?tokenid=A%2Bb+c"), Some(("A+b c".into(), None)));
        assert_eq!(parse_callback("/favicon.ico"), None);
        assert_eq!(parse_callback("/?tokenid=&username=x"), None);
    }

    #[test]
    fn response() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello!!";
        assert_eq!(parse_response(r), Some((200, b"hello".to_vec())));
        let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2;x=y\r\nlo\r\n0\r\n\r\n";
        assert_eq!(parse_response(r), Some((200, b"hello".to_vec())));
        assert_eq!(parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n"), Some((404, vec![])));
        assert_eq!(parse_response(b"garbage"), None);
    }

    #[test]
    fn percent() {
        assert_eq!(percent_decode("a%zz%4"), "a%zz%4");
        assert_eq!(percent_decode("%41%"), "A%");
    }

    #[test]
    fn uid() {
        let u = new_uid();
        assert_eq!(u.len(), 32);
        assert!(u.bytes().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)));
    }
}
