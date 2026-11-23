# fuckforti

**FortiGate IKEv2 IPsec dial-up VPN on Linux, with browser SAML/SSO login** — because
Fortinet ships no Linux client for it and the SSL VPN is going away.

An openfortivpn-style client: it handles the Fortinet-specific SAML handshake itself
and leaves IKEv2/ESP to strongSwan.

## Quick start (prebuilt binary)
The [releases](https://github.com/flokol120/fuckforti/releases) have statically linked
x86_64 binaries that run on any distribution.

**1. Install strongSwan** (plus iproute2 and a running systemd-resolved, which most
desktops already have):

| Distribution | Command |
|---|---|
| Arch, Manjaro | `sudo pacman -S strongswan` |
| Debian, Ubuntu, Mint | `sudo apt install strongswan-charon strongswan-swanctl libstrongswan-standard-plugins libcharon-extra-plugins libcharon-extauth-plugins` |
| Fedora | `sudo dnf install strongswan` |

fuckforti starts its own private `charon`. If the system `strongswan` service is
running, stop it first (`sudo systemctl disable --now strongswan`).

**2. Download and install:**
```sh
V=v0.2.0
curl -LO https://github.com/flokol120/fuckforti/releases/download/$V/fuckforti-$V-x86_64-linux-musl.tar.gz
curl -LO https://github.com/flokol120/fuckforti/releases/download/$V/fuckforti-$V-x86_64-linux-musl.tar.gz.sha256
sha256sum -c fuckforti-$V-x86_64-linux-musl.tar.gz.sha256
tar xzf fuckforti-$V-x86_64-linux-musl.tar.gz && cd fuckforti-$V-x86_64-linux-musl
sudo install -m755 fuckforti /usr/local/bin/
```

**3. Configure:** copy the example config and fill in the values from your FortiClient
VPN profile (gateway, SSO port, local ID, proposals, routes, DNS domains):
```sh
sudo install -Dm600 config.example.toml /etc/fuckforti/config.toml
sudoedit /etc/fuckforti/config.toml
sudo sh -c 'umask 077; cat > /etc/fuckforti/psk'   # paste the pre-shared key, then Ctrl-D
```

**4. Connect:**
```sh
sudo fuckforti        # reads /etc/fuckforti/config.toml; -v for verbose IKE logs
```
Your browser opens for the SSO login. After it completes the tunnel comes up; press
Ctrl-C to disconnect, which removes the interface, routes and DNS again.

The archive also contains the NetworkManager plugin (`nm-fuckforti-service` and the
`nm/` files); see [NetworkManager plugin](#networkmanager-plugin) to install it.

## How it works
1. `POST https://<gw>:<sso_port>/saml_login?` with a client-generated `UID` → the FortiGate returns the SAML login URL.
2. Your browser logs in (IdP, MFA, …). The FortiGate then redirects to `http://127.0.0.1:8020/?tokenid=…&username=…`.
3. A private `charon` instance negotiates IKEv2. The gateway authenticates with the PSK, and the client authenticates with EAP using identity = `UID` and secret = `tokenid`.
4. Traffic runs over an XFRM interface (`forti0`). Routes (split or full tunnel) and DNS (systemd-resolved, per-link split DNS) are set on that interface and removed on exit.

## Requirements
strongSwan ≥ 5.9 (with `charon` and the eap-mschapv2/eap-gtc/eap-md5/eap-identity/resolve plugins), iproute2, systemd-resolved and OpenSSL.
Building needs a Rust toolchain (1.80+).
The system `strongswan` service must not be running.

## Building from source
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

From the release archive, run these from the unpacked directory and use
`nm-fuckforti-service` instead of `target/release/nm-fuckforti-service`. The Plasma
stub isn't in the archive, so build it from source.

```sh
cargo build --release
sudo install -Dm755 target/release/nm-fuckforti-service /usr/lib/fuckforti/nm-fuckforti-service
sudo install -Dm644 nm/nm-fuckforti-service.name /usr/lib/NetworkManager/VPN/nm-fuckforti-service.name
sudo install -Dm644 nm/nm-fuckforti-service.conf /usr/share/dbus-1/system.d/nm-fuckforti-service.conf
sudo systemctl restart NetworkManager

# KDE Plasma only: the tray refuses VPN types without a plasma-nm plugin.
# This metadata-only stub enables connecting from the tray (needs cmake + qt6-base).
cmake -S plasma -B target/plasma -DCMAKE_INSTALL_PREFIX=/usr && cmake --build target/plasma
sudo cmake --install target/plasma

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

## Outages and reconnecting
When the connection drops, the client goes through these stages until one works:

1. **Short outages** (by default up to about 3 minutes, set with `retransmit_tries`):
   the SAs survive and traffic resumes. DPD notices silence after `dpd_delay` seconds.
2. **Network change** (Wi-Fi ↔ Ethernet, new DHCP lease): with MOBIKE (`mobike = true`,
   used only if the gateway offers it) the SA moves to the new address. In full-tunnel
   mode the CLI keeps its host route to the gateway on the current uplink.
3. **SA lost**: the client first tries a new IKE SA with the existing login token, so no
   browser is needed if the gateway accepts it.
4. **New login**: the browser opens again. If the gateway can't be reached, for example
   right after resume, it retries with backoff (2 s up to 60 s) and gives up after 15
   minutes. It does not retry after a cancelled or timed-out login.

The CLI reconnects by default (`--no-reconnect` turns that off). Under NetworkManager,
stages 3 and 4 run only with `vpn.persistent yes`
(`nmcli connection modify forti vpn.persistent yes`). The VPN then stays active in
NetworkManager the whole time. In full-tunnel mode the default route and DNS are
withdrawn during the new login, so the identity provider stays reachable.

## Recovering the pre-shared key
The gateway authenticates with a shared PSK that FortiClient stores obfuscated in its
config. If you don't have the plaintext, ask whoever administers the FortiGate, or read
it from a machine where FortiClient already connects.

## Status / limitations
UDP only (no IPsec-over-TCP fallback), IPv4 only, and no FortiClient EMS/ZTNA posture checks.
Protocol notes are based on <https://github.com/quincampoix/fortigate-saml-vpn> and
<https://github.com/TeaDrinkingProgrammer/archway-vpn>.
