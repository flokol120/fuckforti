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

## NetworkManager plugin
`nm-fuckforti-service` lets NetworkManager run the VPN, so you can connect from the
Plasma/GNOME network applet or with `nmcli`. When you connect, the service opens the
SAML login in the browser of the active desktop session. NetworkManager then applies
the address, routes and DNS. There is no settings GUI yet, so create the connection once
with `nmcli`.

```sh
cargo build --release
sudo install -Dm755 target/release/nm-fuckforti-service /usr/lib/fuckforti/nm-fuckforti-service
sudo install -Dm644 nm/nm-fuckforti-service.name /usr/lib/NetworkManager/VPN/nm-fuckforti-service.name
sudo install -Dm644 nm/nm-fuckforti-service.conf /usr/share/dbus-1/system.d/nm-fuckforti-service.conf
sudo systemctl restart NetworkManager

nmcli connection add type vpn con-name forti ifname '*' \
  vpn-type org.freedesktop.NetworkManager.fuckforti vpn.timeout 300 \
  vpn.data 'gateway=vpn.example.com, saml_port=9443, ike_port=4500, local_id=MY-LOCAL-ID, split_routes=10.0.0.0/8, dns_domains=corp.example.com' \
  vpn.secrets 'psk=THE-PSK'
nmcli connection up forti            # logs: journalctl -u NetworkManager -f
```

`vpn.data` takes the same keys as `config.toml`. Separate list values with spaces or
`;`, because nmcli uses `,` between keys. The PSK is stored as a system secret, so only
root can read it, in `/etc/NetworkManager/system-connections/`. `vpn.timeout 300`
gives the browser login time to finish, since NetworkManager's default is 60 s.

## Recovering the pre-shared key
The gateway authenticates with a shared PSK that FortiClient stores obfuscated in its
config. If you don't have the plaintext, ask whoever administers the FortiGate, or read
it from a machine where FortiClient already connects.

## Status / limitations
UDP only (no IPsec-over-TCP fallback), IPv4 only, and no FortiClient EMS/ZTNA posture checks.
Protocol notes are based on <https://github.com/quincampoix/fortigate-saml-vpn> and
<https://github.com/TeaDrinkingProgrammer/archway-vpn>.
