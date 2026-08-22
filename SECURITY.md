# OneRoof Zigbee security model

This document is the honest version: what is protected, by what, and what
is *not* protected.

## Where encryption applies

| Hop | Encryption | Key |
|---|---|---|
| Device ⇄ coordinator (2.4 GHz) | AES-128-CCM* (Zigbee) | random network key, per install |
| Coordinator ⇄ gateway (USB serial) | none — it is a wire inside your box | — |
| Gateway ⇄ broker | in-process, no network hop at all | — |
| Broker ⇄ Home Assistant / clients (MQTT) | **TLS 1.2+, on by default** | local CA, `data/tls/ca.crt` |
| UI ⇄ browser | HTTPS via HA Ingress (add-on) / HTTPS with local CA if bound off loopback | HA's cert / local CA |
| Secrets on disk | AES-256-GCM keystore, 0600 files | scrypt-derived from passphrase |
| Audit log | not encrypted, but SHA-256 hash-chained (tamper-evident) | — |

## Threat you asked about: someone on the 2.4 GHz band joins the network or injects data

### What stops joining

| Control | Where | Default |
|---|---|---|
| Join window closed at every start and after every window | `Coordinator.start`, `_auto_close` | always |
| Join window hard-capped (never "forever"; ZNP 255 is unreachable) | `commands.zdo_permit_join`, `JoinGuard` | 120 s max |
| Cooldown between windows | `JoinGuard` | 5 s |
| Join window may be pinned to one IEEE address — **detection only** in normal mode: the firmware still hands the key to any device with the public link key; the wrong device is then told to leave and you get an alert. It becomes *prevention* only in strict mode. | `JoinGuard.allowed_ieee` | when `ieee` given |
| Unknown device that joins outside a window or with the wrong IEEE is sent MGMT_LEAVE + alerted (a rogue can ignore the leave — rotate the key if this ever fires) | `Coordinator._on_announce` | always |
| Already-paired devices re-announcing (power cycle, parent change) are recognised as rejoins, never evicted | `Coordinator.known_ieee` | always |
| Firmware opens join without us → immediately closed + alerted | `Coordinator._on_permit_ind` | always |
| **Install codes** (per-device link key, AES-MMO derived) | `security.installcode`, `permit_join(install_code=…)` | optional per join; `permit_join_require_install_code` makes it mandatory |
| **Strict mode**: the public `ZigBeeAlliance09` link key is replaced by a random one → only install-code joins are possible at all | `strict_install_codes: true` | off (breaks devices without install codes) |
| Devices must complete Trust Center link-key update after joining or are kicked | `BDB_SET_TC_REQUIRE_KEY_EXCHANGE=1` | always |
| Rejoin with the public key disabled | `SET_ALLOWREJOIN_TC_POLICY=0` | always |
| Network key, PAN id, ext PAN id random per install | `NetworkSecrets.generate` | always |

### What stops injection / reading

All Zigbee 3.0 frames on the network are AES-128-CCM* encrypted and
authenticated with the network key. Without the key an attacker can see
*that* traffic exists (addresses, lengths, timing) but cannot read payloads or
forge frames — the coordinator firmware drops frames whose MIC fails before
we ever see them.

The network key is exposed **only** at join time, encrypted under the link
key. With the public link key a sniffer present at that moment learns it.
With an install code it does not. That is why install codes matter and why
strict mode exists.

Additionally the gateway raises `security_alert` on:
* `traffic_from_unknown_device` — a short address we have no record of,

* `permit_join_unexpected_open`, `unexpected_join`, `request_denied`.

These go to `oneroof/zigbee/bridge/security` (retained) and are a Home Assistant sensor
out of the box, so you can automate a notification.

### What does NOT protect you (be honest with yourself)

* **Jamming / DoS** of 2.4 GHz. No Zigbee stack can stop it. Mitigation: none
  beyond physical; choose a channel away from your Wi-Fi for reliability.
* **Replay within the same frame counter window** is handled by the firmware's
  frame counters, not by us. We persist nothing about it.
* **A compromised host.** If someone has root on the machine running this,
  they have the network key. The keystore encryption protects against leaked
  backups and support bundles, not against root.
* **Physical access to the dongle.** The key is in the dongle's flash.
* **Devices with bad firmware.** A router that leaks the key is a router that
  leaks the key. Buy from vendors with a track record.
* **Touchlink.** We never enable touchlink commissioning; some bulbs still
  answer touchlink scans from a nearby attacker regardless of coordinator.

## MQTT side

Note: install codes travel in the `permit_join` request payload, so any user
subscribed to `oneroof/zigbee/#` (e.g. Home Assistant) sees them. They are single-use per
device, but if that bothers you, give HA `oneroof/zigbee/+/state` + `oneroof/zigbee/bridge/event`
instead of `oneroof/zigbee/#`.

* Anonymous connections are rejected — there is no setting to allow them.
* Passwords: scrypt (n=2^15), constant-time compare, 0600 file.
* 5 failed login attempts for one username from an IP within 60 s → 30 s lockout for that address+username (everything inside Home Assistant shares one address, so one failing login must not block others); attempts are counted *before* the (expensive) password check, at most 2 checks run concurrently, at most 256 connections total — so parallel guessing cannot bypass the lockout or exhaust memory.
* Retained messages from TCP clients capped at 5000 topics / 16 MiB.
* Per-user ACLs, default deny. The HA user can read state and publish `set`
  commands, but **only users listed as `control_users` can open the join
  window, remove devices or rotate keys**. A leaked HA long-lived token
  therefore cannot admit a device to your Zigbee network.
* **TLS is on by default.** On first start a private CA and a server
  certificate are generated (`data/tls/`, ECDSA P-256, TLS 1.2+, AEAD ciphers
  only). Plaintext MQTT requires an explicit `tls: off`. Give `ca.crt` to Home
  Assistant (MQTT integration → Advanced → "Broker certificate"), or pin the
  fingerprint printed in the log. `tls.mode: custom` for your own cert,
  `client_ca` to require client certificates (mTLS).
* Maximum packet 256 KiB; idle clients dropped at 1.5× keepalive.

## Web UI

The UI exists because pairing from a CLI is not family-friendly, and it is
built to add as little surface as possible:

* Our own ~300-line HTTP server, not a framework. 8 KiB header / 64 KiB body
  limits, one request per connection, 10 s header timeout.
* **Reachable only via Home Assistant Ingress** (HA's login is the login,
  HA's HTTPS is the transport) in the add-on, or loopback when standalone —
  the server refuses any other source address, and the config refuses a
  non-loopback `ui.listen` without an explicit override flag. If you do
  override it, HTTPS with the local CA is forced (`ui.tls` cannot be off off
  loopback).
* All mutating calls need `POST` + JSON + the `X-OneRoof: 1` header, so a
  malicious page in another tab cannot drive it. CSP, `nosniff`, `no-store`
  on every response.
* The UI acts as one named MQTT user (`ui.acts_as`); control actions go
  through the **same** `handle_request` path and `control_users` check as
  MQTT, and are audit-logged as `by: "ui:<user>"`.
* One self-contained HTML file: no CDN, no framework, no build step; device
  names from the radio are rendered as text nodes, never as HTML.

## Inside Home Assistant (add-on)

The add-on registers itself as Home Assistant's MQTT service. Home Assistant's own discovery expects
plain MQTT on the add-on's internal hostname, so the plain listener (1883) is on by default **inside the
add-on network only** — it is not published on a host port unless you enable it in the add-on's Network
section. Traffic between Home Assistant and the add-on never leaves the Docker network. Everything
reachable from your LAN stays TLS (8883).

## Legacy layout (after importing a previous setup)

While the legacy layout is on, the gateway uses *your existing* broker and the
previous topic layout so the migration is invisible to Home Assistant and
other consumers. Two consequences, stated
plainly:

* Transport security is whatever that broker provides (usually plaintext on the
  Docker network). The Zigbee radio, keystore, join policy and audit log are
  unaffected.
* An external broker cannot tell us which user published a request, so **all
  MQTT control requests (permit join, remove, rotate) are refused** in this
  mode; pairing is done from the UI, which acts as a named control user.

Switch to the built-in TLS broker from Settings whenever you are ready.

## Host side (add-on)

* Least privilege, automatically: the add-on starts as root (the Supervisor's device and volume handling assumes it), proves in a child process that an unprivileged user can open the coordinator exactly as configured, and then drops to uid 1000. If that proof fails on a given host it stays root inside its *unprivileged* container like every other add-on, and the log says so. The container requests no host network, no Supervisor/Home Assistant API, no privileged mode. No `hassio_api`, no `host_network`, no
  `privileged`, no `/share` or `/config` mounts, web UI only via Ingress.
* One process, three third-party Python packages (`pyserial-asyncio`,
  `cryptography`, `pyyaml`). `pip audit` takes seconds.
* Secrets at rest: AES-256-GCM keystore + 0600 passphrase file.
* Tamper-evident audit log (SHA-256 hash chain): `python -m oneroof_zigbee verify-audit`.

## Reporting

This is a personal project; review it yourself, it is small enough.

## Login adoption (add-on only)

Home Assistant stores the broker login its MQTT integration was created with and does not take a new
broker announcement while an integration exists. To make the move automatic, the add-on adopts the
login Home Assistant keeps sending: for one hour after an import or the first start, a failed login
**from Home Assistant's own address inside the add-on network** (172.30.32.1/2) for a user that does
not exist yet is accepted once, the user is created with the Home Assistant role (control devices,
cannot open the network), the window closes, and `broker_login_adopted` is written to the audit log.
Existing users with a wrong password are never adopted; the plaintext listener this arrives on is not
reachable from outside Home Assistant unless a host port is mapped. Review or remove the adopted user
under Settings → Users & access at any time.

## Network key rotation

The network key is shared by every device; whoever holds it can read and inject traffic while in
radio range. Two ways to replace it:

* **Over the air** (Settings → Maintenance → Rotate network key): the trust centre hands the new key
  to each device individually, encrypted under that device's own link key, waits a configurable
  window (battery devices collect it from their parent when they wake), then broadcasts the switch.
  Nothing is re-paired. Whoever holds only the old network key cannot read the per-device deliveries
  and is locked out. A device that slept through the window rejoins with its link key and receives
  the current key then. Recorded as `network_key_rotation_started` / `network_key_rotated`.
* **Rotate and re-pair everything**: new key *and* new trust-centre seed on the next start. Required
  when the seed may have leaked as well (it is in the previous setup's backup files alongside the
  key); over-the-air rotation does not exclude someone holding both.

## Liveness and anomaly monitor

Zigbee offers no per-device secure session, so an attacker who obtained the network key cannot be
stopped by the protocol from injecting traffic. What betrays them is behaviour. The gateway keeps a
small behavioural profile per device (persisted) and raises a `device_anomaly` security alert — in
the UI, the Activity log and the Home Assistant "Last security alert" entity — when it sees:

* a ZCL sequence number that jumps far ahead or backwards (an impersonator keeps its own counter);
* link quality far from the device's running average (a different radio in a different place);
* cluster commands from a device that has only ever reported (sensors do not send on/off);
* a burst far above the device's usual peak, and silence right after a burst (the signature of a
  replay that stranded the real device's frame counter);
* a mains-powered device missing its usual cadence by a wide margin (supervised-line liveness).

Thresholds are conservative, one alert per kind per device per 15 minutes, and every alert carries
its evidence.

## Pairing: install codes first, exposure bounded otherwise

* With an install code the network key travels under a key derived from that code; a sniffer learns
  nothing. Strict mode makes this the only way in.
* Without an install code the key travels under the public link key — unavoidable for devices that
  have no code. The gateway bounds that exposure: the window admits **one** device and closes the
  moment it joins (`permit_join_close_after_first_join`), and once the new device has completed its
  trust-centre key exchange the network key is **rotated over the air** (`rotate_key_after_plain_join`,
  on by default), so a key captured during pairing stops working within minutes. Both are settings
  under Settings → Zigbee.

