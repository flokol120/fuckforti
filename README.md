# fuckforti

**FortiGate IKEv2 IPsec dial-up VPN on Linux, with browser SAML/SSO login** — because
Fortinet ships no Linux client for it and the SSL VPN is going away.

An openfortivpn-style client: it handles the Fortinet-specific SAML handshake itself
and leaves IKEv2/ESP to strongSwan.

## How it works
1. `POST https://<gw>:<sso_port>/saml_login?` with a client-generated `UID` → the FortiGate returns the SAML login URL.
2. Your browser logs in (IdP, MFA, …). The FortiGate then redirects to `http://127.0.0.1:8020/?tokenid=…&username=…`.
3. A private `charon` instance negotiates IKEv2. The gateway authenticates with the PSK, and the client authenticates with EAP using identity = `UID` and secret = `tokenid`.
4. Traffic runs over an XFRM interface (`forti0`). Routes (split or full tunnel) and DNS (systemd-resolved, per-link split DNS) are set on that interface and removed on exit.

## Requirements
strongSwan ≥ 5.9 (with `charon` and the eap-mschapv2/eap-gtc/eap-md5/eap-identity/resolve plugins), iproute2, systemd-resolved and OpenSSL.
Building needs a Rust toolchain (1.80+).
The system `strongswan` service must not be running.

## Build & usage
```sh
cargo build --release
sudo install -m755 target/release/fuckforti /usr/local/bin/

cp config.example.toml config.toml   # fill in local_id, ports, routes
echo -n 'THE-PSK' > psk && chmod 600 psk
sudo fuckforti -c config.toml        # -v for verbose IKE logs
```

## Recovering the pre-shared key
The gateway authenticates with a shared PSK that FortiClient stores obfuscated in its
config. If you don't have the plaintext, ask whoever administers the FortiGate, or read
it from a machine where FortiClient already connects.

## Status / limitations
UDP only (no IPsec-over-TCP fallback), IPv4 only, and no FortiClient EMS/ZTNA posture checks.
Protocol notes are based on <https://github.com/quincampoix/fortigate-saml-vpn> and
<https://github.com/TeaDrinkingProgrammer/archway-vpn>.
