# OneRoof Zigbee

**Zigbee gateway + MQTT broker in one app, written from scratch with security first.**
A replacement for *Mosquitto + zigbee2mqtt* for Home Assistant — no vendor code, no
third-party broker, no cloud, no surprises.

[![CI](https://github.com/YOUR_USER/oneroof-zigbee/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USER/oneroof-zigbee/actions/workflows/ci.yml)

> Part of the OneRoof family, alongside OneRoof Bridge and OneRoof NVR.

---

## Why

zigbee2mqtt is excellent software, but its security posture is "configure it
yourself": plaintext MQTT by default, a join window that can stay open, a
well-known default network key, a separate broker with its own logins, and a
web UI exposed on the LAN. OneRoof Zigbee makes the safe thing the only thing:

| | zigbee2mqtt + Mosquitto | OneRoof Zigbee |
|---|---|---|
| Processes | 2 add-ons, 2 configs | **1 process, 1 UI** |
| Network key | default unless you change it | **random per install, encrypted at rest** |
| MQTT | plaintext unless configured | **TLS 1.2+ by default** (own CA, one click for HA) |
| Who may pair devices | anyone with MQTT access | **explicit `control_users`**; HA cannot |
| Join window | can be left open | **capped, auto-closed, cooldown, install codes, strict mode** |
| Unknown device appears | accepted | **evicted + alert** |
| Firmware updates | downloaded from the internet | **only files you upload, verified, per device** |
| Audit | logs | **tamper-evident hash-chained audit log** |
| Code | ~250 k lines + 800 npm packages | **~9 k lines Python, 3 dependencies** |

Read [SECURITY.md](SECURITY.md) — it is the honest version, including what this does *not* protect against.

## What it does

* **Coordinator**: TI CC2652 / CC1352 (Sonoff ZBDongle-P, SMLIGHT SLZB-06/07, ZigStar …) over USB or `tcp://` (network coordinators).
* **Devices**: anything speaking standard ZCL — lights (on/off, dim, colour, CT), plugs with power metering, temperature / humidity / pressure / illuminance / occupancy, IAS contact / motion / leak / smoke, covers, thermostats. Plus standard extras: power-on behaviour, countdown.
* **Built-in MQTT 3.1.1 broker** with users, roles, ACLs, TLS/mTLS, lockout.
* **Home Assistant** auto-discovery; appears in the HA sidebar via Ingress as an add-on.
* **Web UI**: Dashboard, Devices (About / Controls / State / Clusters / Reporting / Bind / Firmware), Pair, Map, Logs, Activity, Settings (full admin console with help on every setting).
* **Migrate from zigbee2mqtt without re-pairing** (same dongle).
* **Backups** (encrypted), **OTA** (local, verified), **import**, **restart** — all from the UI.

Not yet: Tuya/Aqara private clusters (child lock, indicator mode …), groups & scenes, Silicon Labs (EZSP) dongles, touchlink.

## Install

### Home Assistant add-on

1. Settings → Add-ons → Add-on store → ⋮ → Repositories → add this repository URL.
2. Install **OneRoof Zigbee**, set the serial port, start it.
3. The log shows the MQTT passwords **once** and the CA certificate path.
4. Settings → Devices & services → Add integration → **MQTT**: broker = the HA host,
   port **8883**, TLS on, user `homeassistant`, upload the CA as *Broker certificate*.
5. Open OneRoof Zigbee in the sidebar → Pair.

### Standalone

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
cp config.example.yaml config.yaml            # set serial.port
.venv/bin/python -m oneroof_zigbee passwd admin
.venv/bin/python -m oneroof_zigbee passwd homeassistant
.venv/bin/python -m oneroof_zigbee run -c config.yaml
```

UI: http://127.0.0.1:8099 (loopback only by design; use `ssh -L 8099:localhost:8099 host` from elsewhere).
MQTT: port 8883, TLS, CA at `data/tls/ca.crt`.

## Migrating from zigbee2mqtt (no re-pairing)

Keep the **same coordinator dongle** — the network lives in its flash.

* **UI**: Settings → *Import from zigbee2mqtt* → upload `configuration.yaml`, `database.db`
  and (optional) `coordinator_backup.json` → Preview → Import → Restart.
* **CLI**: `oneroof-zigbee import-z2m /path/to/zigbee2mqtt --apply`

We adopt the same network key / PAN / channel so the coordinator simply starts
instead of re-forming, and import names, models and endpoints so no interview
is needed. If the dongle was wiped or replaced, `coordinator_backup.json` is
required: we re-form with the same key and a higher frame counter and devices
rejoin on their own. If zigbee2mqtt used its public default key, the import
flags it — rotate it once everything works.

## Firmware updates (OTA)

Strictly local. Upload `.ota` files under Settings → *Firmware library*; the header is
parsed and verified (manufacturer, image type, version, size, SHA-256). A file is
offered only to a device whose own report matches, only when newer, and only when
you press *Update* for that one device. The gateway never downloads firmware.

## Pairing

* **Pair page** → *Open join window* (max 120 s by default, auto-closes).
* **Install code** (recommended; the only way in strict mode): type the device's IEEE
  and the code printed on it — the network key is then never sent under the public
  ZigBeeAlliance09 key.
* Only **control users** (and the UI acting as one) can open the window. Home
  Assistant's user cannot, on purpose.

## Layout

```
oneroof_zigbee/
  znp/        UNPI framing, ZNP commands, async transport, coordinator bring-up
  zcl/        ZCL codec, data types, global commands, cluster converters
  mqtt/       MQTT 3.1.1 broker (auth, ACL, TLS, retained, QoS1) + client
  security/   install codes (AES-MMO), encrypted keystore, local CA, join guard, audit log
  ui/         own HTTP/SSE server, JSON API, single-file web UI
  ha/         Home Assistant discovery
  admin.py    users/roles, config editor, backup/restore, restart
  importer.py zigbee2mqtt import
  ota.py      OTA upgrade server (local, verified)
  gateway.py  orchestration
addon/        Home Assistant add-on (non-root, Ingress-only UI)
tests/        unit, integration, end-to-end (stack + real browser)
docs/         architecture, UI API contract
```

## Tests

```bash
./e2e.sh          # lint + 279 tests: unit, integration, end-to-end stack, browser (skips without Chrome)
```

The end-to-end suite boots the production entry point with a simulated coordinator
and simulated ZCL devices and drives it over real TLS MQTT, the HTTP API and a real
Chrome: pairing, interviews, discovery, control, reports, security denials,
eviction, lockout, users, config, backup/restore, OTA transfer, import, shutdown.

## Status

Everything above is implemented and tested against simulated hardware; it has
**not yet been run against a physical dongle**. Expect to iterate on the first real pairing.

## License

Source-available, see [LICENSE](LICENSE).
