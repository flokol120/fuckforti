# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`fuckforti` is a Linux client for **FortiGate IKEv2 IPsec dial-up VPNs that use
browser SAML/SSO login**. Fortinet ships no Linux client for this mode, and the
SSL VPN it replaces is being retired. The client performs the Fortinet-specific
SAML pre-authentication handshake itself and leaves IKEv2/ESP to a private
strongSwan `charon` instance driven over VICI.

Written in Rust (edition 2021, toolchain 1.80+). Linux-only, IPv4-only, UDP-only.

## Golden rules

- **Never commit secrets or site-specific data.** No pre-shared keys, tokens,
  real gateway hostnames, user identities, or captured traffic. `config.toml`,
  `psk`, `*.conf` (except `nm/*.conf`), and `*.pcap` are gitignored — keep it
  that way. Check `git status` before committing and never `git add -f` an
  ignored path.
- **The plaintext PSK is an input, not something this project derives.** The
  client reads it from config (`psk_file` or `psk`). Do not add code, docs, or
  comments about extracting, recovering, decrypting, or reverse-engineering
  credentials from FortiClient or any other vendor software. That is out of
  scope for this repository.
- **Document only the on-the-wire protocol.** Keep the project interoperability-
  focused: no vendor binaries, no decompiled code, no vendor-internal constants.
- **Don't widen defaults to real networks.** Keep examples generic
  (`vpn.example.com`, `10.0.0.0/8`, `corp.example.com`). Never hardcode a real
  subnet, domain, or gateway.

## Layout

```
src/lib.rs      Shared library: session lifecycle (lock_rundir, shutdown,
                monitor/reconnect loop). Used by both binaries below.
src/main.rs     `fuckforti` CLI entry point (arg parsing, signal handling).
src/bin/nm-fuckforti-service.rs
                `nm-fuckforti-service`: NetworkManager VPN plugin (zbus/D-Bus).
src/config.rs   Config model + parsing from TOML (CLI) and from NM vpn.data.
src/charon.rs   Private strongSwan charon instance: config generation, start/
                stop, secrets, DNS-to-file handling.
src/vici.rs     VICI protocol client (talks to charon over its unix socket).
src/saml.rs     Fortinet SAML pre-auth handshake + opening the browser login.
src/net.rs      XFRM tunnel interface (forti0), routes, DNS (systemd-resolved).
src/error.rs    Error/Result types.
nm/             NetworkManager service metadata + D-Bus policy.
plasma/         Metadata-only KDE plasma-nm stub (enables connecting from the
                Plasma tray; no settings GUI).
packaging/arch/ AUR PKGBUILD (split: fuckforti + fuckforti-plasma) + install hook.
config.example.toml   Annotated example config — keep values generic.
```

Tests live inline (`#[cfg(test)]`) in `charon.rs`, `config.rs`, `vici.rs`,
`net.rs`, `saml.rs`, and the NM service binary (~20 unit tests).

## Build, test, run

```sh
cargo build --release          # builds fuckforti + nm-fuckforti-service
cargo test                     # unit tests (no root, no network needed)
cargo clippy --all-targets     # keep it clean before committing
cargo fmt
```

Running the VPN needs root, strongSwan, iproute2, and systemd-resolved, and the
system `strongswan` service must be stopped. The full install/usage flow (CLI
and NetworkManager) is in `README.md` — prefer updating that over duplicating
steps here.

## Conventions & gotchas

- **One session at a time.** The binary enforces this via an interface name
  check, a live VICI socket check, and an flock on `/run/fuckforti` (see
  `lock_rundir`). Don't bypass these.
- **Clean teardown is mandatory.** `shutdown()` closes the SA, wipes secrets,
  removes the interface/routes/DNS, and stops charon. Any new resource a session
  creates must be undone there, including on error and signal paths.
- **The SAML request keeps its literal trailing `?`.** FortiGate only answers
  `POST /saml_login?` with the `?` present; URL libraries strip it, so that
  request is hand-rolled. Don't "fix" it by routing it through a URL builder.
- **Keep the two front-ends in sync.** CLI and NetworkManager share `lib.rs`;
  `config.rs` parses both TOML and NM `vpn.data` into the same model. Changes to
  config fields usually need both paths plus `config.example.toml` and the README.
- **`nm/*.conf` is intentionally not ignored** (it's D-Bus policy, not a secret);
  the `.gitignore` has an explicit `!nm/*.conf` exception. Keep inline `#`
  comments off pattern lines in `.gitignore` — they break the pattern.

## Commits

- Branch off `main`; don't commit directly to it unless asked.
- Commit or push only when the user asks.
- Conventional, imperative subject lines (see `git log`).
