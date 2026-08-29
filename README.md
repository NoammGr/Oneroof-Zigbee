# OneRoof Zigbee

**A Zigbee gateway with a built-in MQTT broker for Home Assistant, designed around security.**
One process, one UI: pair your Zigbee devices, and Home Assistant connects straight to it.

[![CI](https://github.com/NoammGr/Oneroof-Zigbee/actions/workflows/ci.yml/badge.svg)](https://github.com/NoammGr/Oneroof-Zigbee/actions/workflows/ci.yml)

> Part of the OneRoof family, alongside [OneRoof Bridge](https://github.com/NoammGr/oneroof-bridge), [OneRoof NVR](https://github.com/NoammGr/oneroof-nvr) and [OneRoof Energy](https://github.com/NoammGr/Oneroof-Energy).

---

## Principles

OneRoof Zigbee is written from scratch so that every security decision could be made on purpose:

| Principle | How |
|---|---|
| **Secure by default** | Random network key per install, encrypted at rest. TLS 1.2+ for MQTT out of the box with a generated local CA. |
| **Least privilege** | Only explicit *control users* may pair devices, remove them or rotate keys. Home Assistant's own user can control devices but cannot open the network. |
| **A short, guarded join window** | Capped and auto-closing, with cooldown; install-code pairing; an optional strict mode that only admits devices with install codes. |
| **Nothing uninvited** | A device appearing outside a join window is removed and raises an alert. Firmware comes only from files you upload and verify — the gateway never downloads anything. |
| **Everything accountable** | A tamper-evident, hash-chained audit log records who did what; security alerts are published to Home Assistant. A behavioural monitor flags impersonation, bursts and devices that go silent; the network key can be rotated over the air without re-pairing. |
| **Small enough to read** | About 9 k lines of Python and three dependencies. The UI is a single file that makes no external requests. |

Read [SECURITY.md](SECURITY.md) for the full model, including what this does *not* protect against.

## What it does

* **Coordinator**: TI CC2652 / CC1352 (Sonoff ZBDongle-P, SMLIGHT SLZB-06/07, ZigStar …) over USB or `tcp://` (network coordinators).
* **Devices**: anything speaking standard ZCL — lights (on/off, dim, colour, CT), plugs with power metering, temperature / humidity / pressure / illuminance / occupancy, IAS contact / motion / leak / smoke / CO / vibration, covers, thermostats, door locks, remotes and buttons (as `action` events). Plus standard extras: power-on behaviour, countdown.
* **Model knowledge** for the common makes, so a device shows up as what it is (contact sensor, 2-gang wall switch, TRV, remote…) instead of whatever its clusters suggest: Aqara/Xiaomi (structured battery/temperature/contact reports, multi-gang switches, buttons, plugs, curtain), Tuya (TS00xx switches, plugs with child lock and indicator, buttons, sensors, lights, and TS0601 datapoint devices: temperature/humidity, TRVs, wall thermostats, curtains, presence radars, generic datapoint fallback), IKEA (bulbs, drivers, plugs, remotes, motion, contact, leak, blinds), Philips Hue (bulbs, dimmer, motion, buttons), Sonoff, Innr, OSRAM/LEDVANCE, SmartThings/Centralite, Heiman, frient/Develco, Third Reality, Danfoss, Eurotronic, Bosch, Yale/Kwikset/Schlage locks, Ubisys, Gledopto, Paulmann, Müller Licht, LiXee, Visonic, Xfinity, Linkind, Namron, Sunricher, Aurora, Lidl, Legrand/Netatmo, Schneider. Unknown models fall back to cluster heuristics with a device-level kind.
* **Unknown Tuya datapoint devices** are not a dead end: the gateway remembers every datapoint id and wire type a device reports, infers the product family from Tuya's conventional layouts when the evidence fits exactly one family (thermostat, curtain, temperature/humidity, smoke, presence radar, multi-gang switch, soil, light, siren), and marks those features *inferred*. Anything ambiguous stays a raw `dp_<n>` value.
* **Teach it**: a Datapoints tab on the device page lets you name each datapoint (key, type, scale, unit, labels, device class …) and a Type & category card overrides what any model is; both are saved as a *definition* for that model in `definitions.yaml`, take precedence over the built-in table, apply to every device of the model without a restart and are re-announced to Home Assistant. Definitions can be exported and imported as YAML (Settings → Device definitions).
* **Built-in MQTT broker** (3.1.1 and 5 clients) with users, roles, ACLs, TLS/mTLS, lockout.
* **Home Assistant** auto-discovery; appears in the HA sidebar via Ingress as an add-on. Registers itself as Home Assistant's MQTT service, so One Roof Bridge (Apple Home) and One Roof NVR connect automatically and build on the device descriptions published on `bridge/devices`.
* **Web UI**: Dashboard, Devices (About / Controls / State / Datapoints / Clusters / Reporting / Bind / Firmware), Pair, Map, Logs, Activity, Settings (full admin console with help on every setting).
* **Migrate from a previous setup without re-pairing** (same dongle) — same broker, topics and HA entities.
* **Backups** (encrypted), **OTA** (local, verified), **import**, **restart** — all from the UI.
* **Telegram notifications** (optional, off by default) for security and network events — names, not addresses; batched, rate-limited, quiet hours. The gateway makes no other outbound connection, and the one it can make is allow-listed, TLS-verified and listed in a ledger you can check under Settings → Outbound connections.

Not yet: built-in datapoint maps for every Tuya model (unknown ones are inferred conservatively or taught by hand; the inference knows no irrigation or air-quality layouts yet), Aqara private settings (power outage memory, sensitivity …), groups & scenes, Silicon Labs (EZSP) dongles, touchlink.

## Install

### Home Assistant add-on

1. Settings → Add-ons → Add-on store → ⋮ → Repositories → add `https://github.com/NoammGr/Oneroof-Zigbee`.
2. Install **One Roof Zigbee**. Configuration → `serial_port`: pick your adapter. Start.
3. That's it for a new network: One Roof Zigbee registers itself as Home Assistant's MQTT service,
   so the MQTT integration and add-ons that auto-detect the broker connect to it by themselves.
   Open the UI from the sidebar → Pair.

**Coming from a previous setup** (existing devices, broker add-on, dashboards):
1. Stop the old Zigbee add-on and the old broker add-on (don't uninstall yet).
2. Install and start One Roof Zigbee as above.
3. Sidebar → One Roof Zigbee → Settings → *Import a previous setup* → **Use this folder** (the old
   folder is found on this Home Assistant; uploads work too) → Import → Restart.
4. Nothing else. Home Assistant keeps retrying its existing broker login from inside the add-on
   network; for one hour after the import (or the first start) the add-on adopts that login, records
   it in the audit log (`broker_login_adopted`) and Home Assistant is connected without any change on
   its side. (You can instead point the MQTT integration at the add-on yourself: Settings → Devices &
   services → MQTT → Configure → broker = the add-on hostname from its log, port 1883, any user from
   Settings → Users & access.)

Everything else is automatic: same network (no re-pairing), same topics and Home Assistant
entities (dashboards, automations, history untouched), add-ons that auto-detect the broker repointed
through the Supervisor, and the previous broker login recreated so clients outside Home Assistant
keep connecting. When all is well, uninstall the old add-ons.

### Standalone

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
cp docs/config.example.yaml config.yaml            # set serial.port
.venv/bin/python -m oneroof_zigbee passwd admin
.venv/bin/python -m oneroof_zigbee passwd homeassistant
.venv/bin/python -m oneroof_zigbee run -c config.yaml
```

UI: http://127.0.0.1:8099 (loopback only by design; use `ssh -L 8099:localhost:8099 host` from elsewhere).
MQTT: port 8883, TLS, CA at `data/tls/ca.crt`.

## Migrating from a previous setup (nothing else changes)

Keep the **same coordinator dongle** — the network lives in its flash. Import the old files
(UI: Settings → *Import a previous setup*; CLI: `oneroof-zigbee import /path/to/old/data --apply`).

The import does the whole move:

* **Same network** — adopts the existing key / PAN / channel so the coordinator starts instead of
  re-forming; names, models and endpoints are imported, so no interview runs and no device is re-paired.
* **Same topics and entities** — the previous `<base>/<friendly name>` layout and discovery identities,
  so Home Assistant keeps the *same* entities: ids, names, areas, history, automations, cards.
* **Same clients** — in the add-on, One Roof Zigbee registers as Home Assistant's MQTT service, so the
  MQTT integration and auto-detecting add-ons switch over by themselves; the previous broker login is
  recreated for clients outside Home Assistant.

If the dongle was wiped or replaced, `coordinator_backup.json` is required: we re-form with the same
key and a higher frame counter and devices rejoin on their own. If the previous setup used a well-known
default network key, the import flags it — rotate it once everything works (the one step that re-pairs).

Standalone (outside the add-on) you can instead keep an *existing broker* (`mqtt.external`) — the import
offers it when the old config names one.

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
addon/                   Home Assistant add-on: config, Dockerfile, run.py — and the gateway itself:
addon/oneroof_zigbee/
  znp/        UNPI framing, ZNP commands, async transport, coordinator bring-up
  zcl/        ZCL codec, data types, global commands, cluster converters
  mqtt/       MQTT broker for 3.1.1 and 5 clients (auth, ACL, TLS, retained, QoS1) + client
  security/   install codes (AES-MMO), encrypted keystore, local CA, join guard, audit log
  ui/         own HTTP/SSE server, JSON API, single-file web UI
  ha/         Home Assistant discovery
  admin.py    users/roles, config editor, backup/restore, restart
  importer.py import of a previous setup
  ota.py      OTA upgrade server (local, verified)
  gateway.py  orchestration
tests/        unit, integration, end-to-end (stack + real browser)
docs/         architecture, UI API contract
```

## Tests

```bash
tests/e2e.sh      # lint + 297 tests: unit, integration, end-to-end stack, browser (skips without Chrome)
```

The end-to-end suite boots the production entry point with a simulated coordinator
and simulated ZCL devices and drives it over real TLS MQTT, the HTTP API and a real
Chrome: pairing, interviews, discovery, control, reports, security denials,
eviction, lockout, users, config, backup/restore, OTA transfer, import, shutdown.

## Status

Tested against simulated hardware and, since 1.2.4, against a real Sonoff ZBDongle-P (Z-Stack 3.x.0)
during its first bring-up; expect to iterate on the first real pairings.

## License

Source-available, see [LICENSE](LICENSE).

## Versions

Releases are tagged `vX.Y.Z` and listed in [CHANGELOG.md](CHANGELOG.md). Pushing `main` auto-creates
the tag for the version in `pyproject.toml`; the tag triggers the release workflow: tests → add-on images on GHCR (amd64, aarch64) → GitHub Release. The add-on's
`version` in `addon/config.yaml` and `oneroof_zigbee.__version__` must match the tag.
