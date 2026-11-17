//! Minimal client for strongSwan's VICI protocol (the subset fuckforti needs).
//!
//! Wire format: each packet is a big-endian u32 length followed by a type byte,
//! an optional name (u8 length + bytes) and an optional message. A message is a
//! sequence of elements: sections, key/values and lists.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
const EVENT_REGISTER: u8 = 3;
const EVENT_UNREGISTER: u8 = 4;
const EVENT_CONFIRM: u8 = 5;
const EVENT_UNKNOWN: u8 = 6;
const EVENT: u8 = 7;

const SECTION_START: u8 = 1;
const SECTION_END: u8 = 2;
const KEY_VALUE: u8 = 3;
const LIST_START: u8 = 4;
const LIST_ITEM: u8 = 5;
const LIST_END: u8 = 6;

const MAX_PACKET: usize = 1 << 20;
const TICK: Duration = Duration::from_millis(250);

fn verr<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Charon(msg.into()))
}

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(Vec<u8>),
    List(Vec<Vec<u8>>),
    Sec(Msg),
}

/// An ordered VICI message.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Msg(pub Vec<(String, Val)>);

impl Msg {
    pub fn new() -> Self {
        Msg(Vec::new())
    }

    pub fn kv(mut self, k: &str, v: impl AsRef<[u8]>) -> Self {
        self.0.push((k.into(), Val::Str(v.as_ref().to_vec())));
        self
    }

    pub fn list<I, S>(mut self, k: &str, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        self.0.push((k.into(), Val::List(items.into_iter().map(|s| s.as_ref().to_vec()).collect())));
        self
    }

    pub fn sec(mut self, k: &str, m: Msg) -> Self {
        self.0.push((k.into(), Val::Sec(m)));
        self
    }

    pub fn get(&self, k: &str) -> Option<&Val> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }

    pub fn str(&self, k: &str) -> Option<&[u8]> {
        match self.get(k) {
            Some(Val::Str(v)) => Some(v),
            _ => None,
        }
    }

    pub fn section(&self, k: &str) -> Option<&Msg> {
        match self.get(k) {
            Some(Val::Sec(m)) => Some(m),
            _ => None,
        }
    }

    pub fn list_of(&self, k: &str) -> &[Vec<u8>] {
        match self.get(k) {
            Some(Val::List(l)) => l,
            _ => &[],
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        for (name, val) in &self.0 {
            let tag = match val {
                Val::Str(_) => KEY_VALUE,
                Val::List(_) => LIST_START,
                Val::Sec(_) => SECTION_START,
            };
            out.push(tag);
            put_name(out, name)?;
            match val {
                Val::Str(v) => put_value(out, v)?,
                Val::List(items) => {
                    for it in items {
                        out.push(LIST_ITEM);
                        put_value(out, it)?;
                    }
                    out.push(LIST_END);
                }
                Val::Sec(m) => {
                    m.encode(out)?;
                    out.push(SECTION_END);
                }
            }
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> Result<Msg> {
        let mut c = Cursor(data);
        let mut stack: Vec<(String, Msg)> = vec![(String::new(), Msg::new())];
        while !c.0.is_empty() {
            match c.u8()? {
                SECTION_START => {
                    let n = c.name()?;
                    stack.push((n, Msg::new()));
                }
                SECTION_END => {
                    if stack.len() < 2 {
                        return verr("VICI: unbalanced section end");
                    }
                    let (n, m) = stack.pop().unwrap();
                    stack.last_mut().unwrap().1 .0.push((n, Val::Sec(m)));
                }
                KEY_VALUE => {
                    let n = c.name()?;
                    let v = c.value()?;
                    stack.last_mut().unwrap().1 .0.push((n, Val::Str(v)));
                }
                LIST_START => {
                    let n = c.name()?;
                    let mut items = Vec::new();
                    loop {
                        match c.u8()? {
                            LIST_ITEM => items.push(c.value()?),
                            LIST_END => break,
                            t => return verr(format!("VICI: unexpected element {t} in list")),
                        }
                    }
                    stack.last_mut().unwrap().1 .0.push((n, Val::List(items)));
                }
                t => return verr(format!("VICI: unknown element type {t}")),
            }
        }
        if stack.len() != 1 {
            return verr("VICI: unterminated section");
        }
        Ok(stack.pop().unwrap().1)
    }
}

fn put_name(out: &mut Vec<u8>, name: &str) -> Result<()> {
    let len = u8::try_from(name.len()).or_else(|_| verr("VICI: name too long"))?;
    out.push(len);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

fn put_value(out: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    let len = u16::try_from(v.len()).or_else(|_| verr("VICI: value too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(v);
    Ok(())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return verr("VICI: truncated message");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn name(&mut self) -> Result<String> {
        let n = self.u8()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn value(&mut self) -> Result<Vec<u8>> {
        let b = self.take(2)?;
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        Ok(self.take(n)?.to_vec())
    }
}

enum Packet {
    Response(Msg),
    Unknown,
    Confirm,
    EventUnknown,
    Event(String, Msg),
}

fn parse_packet(body: &[u8]) -> Result<Packet> {
    let mut c = Cursor(body);
    Ok(match c.u8()? {
        CMD_RESPONSE => Packet::Response(Msg::decode(c.0)?),
        CMD_UNKNOWN => Packet::Unknown,
        EVENT_CONFIRM => Packet::Confirm,
        EVENT_UNKNOWN => Packet::EventUnknown,
        EVENT => {
            let name = c.name()?;
            Packet::Event(name, Msg::decode(c.0)?)
        }
        t => return verr(format!("VICI: unexpected packet type {t}")),
    })
}

/// Turn a command response into an error if it reports `success = no`.
fn check(cmd: &str, m: Msg) -> Result<Msg> {
    if m.str("success") == Some(b"no") {
        let why = m.str("errmsg").map(|e| String::from_utf8_lossy(e).into_owned());
        return verr(why.unwrap_or_else(|| format!("{cmd} failed")));
    }
    Ok(m)
}

pub struct Session {
    sock: UnixStream,
    buf: Vec<u8>,
    /// When set, blocking reads give up with `Error::Interrupted`.
    stop: Option<Arc<AtomicBool>>,
    /// Upper bound for waiting on a single response.
    timeout: Duration,
}

impl Session {
    pub fn connect(path: &Path, stop: Option<Arc<AtomicBool>>) -> Result<Session> {
        let sock = UnixStream::connect(path)
            .map_err(|e| Error::Charon(format!("cannot connect to {}: {e}", path.display())))?;
        sock.set_read_timeout(Some(TICK)).ok();
        sock.set_write_timeout(Some(Duration::from_secs(10))).ok();
        Ok(Session { sock, buf: Vec::new(), stop, timeout: Duration::from_secs(120) })
    }

    fn send(&mut self, ptype: u8, name: &str, msg: Option<&Msg>) -> Result<()> {
        let mut body = vec![ptype];
        put_name(&mut body, name)?;
        if let Some(m) = msg {
            m.encode(&mut body)?;
        }
        let mut pkt = (body.len() as u32).to_be_bytes().to_vec();
        pkt.extend_from_slice(&body);
        self.sock.write_all(&pkt).or_else(|e| verr(format!("VICI write: {e}")))
    }

    /// Read one packet. With `poll`, returns `Ok(None)` if nothing arrived in that time.
    fn recv(&mut self, poll: Option<Duration>) -> Result<Option<Packet>> {
        let start = Instant::now();
        let mut tmp = [0u8; 8192];
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                if len > MAX_PACKET {
                    return verr("VICI: oversized packet");
                }
                if self.buf.len() >= 4 + len {
                    let body: Vec<u8> = self.buf.drain(..4 + len).skip(4).collect();
                    return parse_packet(&body).map(Some);
                }
            }
            match self.sock.read(&mut tmp) {
                Ok(0) => return verr("VICI connection closed"),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if self.stop.as_ref().is_some_and(|s| s.load(Ordering::SeqCst)) {
                        return Err(Error::Interrupted);
                    }
                    let waited = start.elapsed();
                    if poll.is_some_and(|p| waited >= p) {
                        return Ok(None);
                    }
                    if waited >= self.timeout {
                        return verr("timed out waiting for charon");
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return verr(format!("VICI read: {e}")),
            }
        }
    }

    fn recv_blocking(&mut self) -> Result<Packet> {
        loop {
            if let Some(p) = self.recv(None)? {
                return Ok(p);
            }
        }
    }

    /// Send a simple command and return its (successful) response.
    pub fn request(&mut self, cmd: &str, msg: &Msg) -> Result<Msg> {
        self.send(CMD_REQUEST, cmd, Some(msg))?;
        loop {
            match self.recv_blocking()? {
                Packet::Response(m) => return check(cmd, m),
                Packet::Unknown => return verr(format!("charon does not know the VICI command {cmd}")),
                Packet::Event(..) => {}
                _ => return verr(format!("VICI: unexpected reply to {cmd}")),
            }
        }
    }

    /// Send a command that streams `event` messages before its final response.
    pub fn streamed(&mut self, cmd: &str, event: &str, msg: &Msg, mut on_event: impl FnMut(&Msg)) -> Result<Msg> {
        self.register(event)?;
        self.send(CMD_REQUEST, cmd, Some(msg))?;
        let res = loop {
            match self.recv_blocking()? {
                Packet::Event(name, m) if name == event => on_event(&m),
                Packet::Event(..) => {}
                Packet::Response(m) => break check(cmd, m),
                Packet::Unknown => break verr(format!("charon does not know the VICI command {cmd}")),
                _ => break verr(format!("VICI: unexpected reply to {cmd}")),
            }
        };
        self.unregister(event)?;
        res
    }

    pub fn register(&mut self, event: &str) -> Result<()> {
        self.event_ctl(EVENT_REGISTER, event)
    }

    fn unregister(&mut self, event: &str) -> Result<()> {
        self.event_ctl(EVENT_UNREGISTER, event)
    }

    fn event_ctl(&mut self, ptype: u8, event: &str) -> Result<()> {
        self.send(ptype, event, None)?;
        loop {
            match self.recv_blocking()? {
                Packet::Confirm => return Ok(()),
                Packet::EventUnknown => return verr(format!("charon does not know the VICI event {event}")),
                Packet::Event(..) => {}
                _ => return verr("VICI: unexpected reply to event (un)registration"),
            }
        }
    }

    /// Wait up to `poll` for the next event of a registered stream.
    pub fn next_event(&mut self, poll: Duration) -> Result<Option<(String, Msg)>> {
        match self.recv(Some(poll))? {
            None => Ok(None),
            Some(Packet::Event(n, m)) => Ok(Some((n, m))),
            Some(_) => verr("VICI: unexpected packet while listening"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = Msg::new()
            .kv("a", "1")
            .list("l", ["x", "yz"])
            .list("empty", Vec::<&str>::new())
            .sec("s", Msg::new().kv("b", b"\x00\xff").sec("inner", Msg::new()));
        let mut buf = Vec::new();
        m.encode(&mut buf).unwrap();
        assert_eq!(&buf[..7], b"\x03\x01a\x00\x011\x04");
        assert_eq!(Msg::decode(&buf).unwrap(), m);
        assert_eq!(m.section("s").unwrap().str("b"), Some(&b"\x00\xff"[..]));
        assert_eq!(m.list_of("l"), [b"x".to_vec(), b"yz".to_vec()]);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Msg::decode(b"\x02").is_err());
        assert!(Msg::decode(b"\x01\x01s").is_err());
        assert!(Msg::decode(b"\x03\x01a\x00\x05ab").is_err());
    }

    #[test]
    fn failed_response() {
        let m = Msg::new().kv("success", "no").kv("errmsg", "nope");
        assert_eq!(check("x", m).unwrap_err().to_string(), "nope");
    }
}
