# OneRoof Zigbee

**A Zigbee gateway with a built-in MQTT broker for Home Assistant, designed around security.**
One process, one UI: pair your Zigbee devices, and Home Assistant connects straight to it.

[![CI](https://github.com/NoammGr/Oneroof-Zigbee/actions/workflows/ci.yml/badge.svg)](https://github.com/NoammGr/Oneroof-Zigbee/actions/workflows/ci.yml)

> Part of the OneRoof family, alongside OneRoof Bridge and OneRoof NVR.

---

## Principles

OneRoof Zigbee is written from scratch so that every security decision could be made on purpose:

| Principle | How |
|---|---|
| **Secure by default** | Random network key per install, encrypted at rest. TLS 1.2+ for MQTT out of the box with a generated local CA. |
| **Least privilege** | Only explicit *control users* may pair devices, remove them or rotate keys. Home Assistant's own user can control devices but cannot open the network. |
| **A short, guarded join window** | Capped and auto-closing, with cooldown; install-code pairing; an optional strict mode that only admits devices with install codes. |
| **Nothing uninvited** | A device appearing outside a join window is removed and raises an alert. Firmware comes only from files you upload and verify — the gateway never downloads anything. |
| **Everything accountable** | A tamper-evident, hash-chained audit log records who did what; security alerts are published to Home Assistant. |
| **Small enough to read** | About 9 k lines of Python and three dependencies. The UI is a single file that makes no external requests. |

Read [SECURITY.md](SECURITY.md) for the full model, including what this does *not* protect against.

## What it does

* **Coordinator**: TI CC2652 / CC1352 (Sonoff ZBDongle-P, SMLIGHT SLZB-06/07, ZigStar …) over USB or `tcp://` (network coordinators).
* **Devices**: anything speaking standard ZCL — lights (on/off, dim, colour, CT), plugs with power metering, temperature / humidity / pressure / illuminance / occupancy, IAS contact / motion / leak / smoke, covers, thermostats. Plus standard extras: power-on behaviour, countdown.
* **Built-in MQTT 3.1.1 broker** with users, roles, ACLs, TLS/mTLS, lockout.
* **Home Assistant** auto-discovery; appears in the HA sidebar via Ingress as an add-on.
* **Web UI**: Dashboard, Devices (About / Controls / State / Clusters / Reporting / Bind / Firmware), Pair, Map, Logs, Activity, Settings (full admin console with help on every setting).
* **Migrate from a previous setup without re-pairing** (same dongle) — same broker, topics and HA entities.
* **Backups** (encrypted), **OTA** (local, verified), **import**, **restart** — all from the UI.

Not yet: Tuya/Aqara private clusters (child lock, indicator mode …), groups & scenes, Silicon Labs (EZSP) dongles, touchlink.

## Install

### Home Assistant add-on

1. Settings → Add-ons → Add-on store → ⋮ → Repositories → add `https://github.com/NoammGr/Oneroof-Zigbee`.
2. Install **OneRoof Zigbee** (the first install builds the image on your HA host, a few minutes),
   set the serial port, start it.
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

## Migrating from a previous setup (nothing else changes)

Keep the **same coordinator dongle** — the network lives in its flash. Then:

1. Stop your previous gateway add-on (leave your MQTT broker running).
2. Install OneRoof Zigbee with the same serial port.
3. Settings → *Import a previous setup* → upload its `configuration.yaml`, `coordinator_backup.json`,
   and if present `database.db` and `state.json` → Preview → Import → Restart.

The import does three things so that **nothing downstream notices**:

* **Same network** — adopts the existing network key / PAN / channel, so the coordinator
  starts instead of re-forming; device names, models and endpoints are imported, so no
  interviews run and no device is re-paired.
* **Same broker** — keeps using your existing MQTT broker (server/login from
  `configuration.yaml`; the built-in broker stays off until you switch). Home Assistant's
  MQTT integration, OneRoof Bridge, OneRoof NVR and any dashboard keep their connection as is.
* **Same topics and entities** — the previous `<base>/<friendly name>` topic layout and the
  same Home Assistant discovery identities, so HA keeps the *same* entities: entity ids,
  names, areas, history, automations, Lovelace cards.

Later, from Settings, you can turn on the built-in TLS broker and point clients at it —
at your pace. If the dongle was wiped or replaced, `coordinator_backup.json` is required:
we re-form with the same key and a higher frame counter and devices rejoin on their own.
If the previous setup used a well-known default network key, the import flags it — rotate
it once everything works (that is the one step that re-pairs devices).

CLI equivalent: `oneroof-zigbee import /path/to/previous/data --apply`.

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
  importer.py import of a previous setup
  ota.py      OTA upgrade server (local, verified)
  gateway.py  orchestration
oneroof-zigbee/  Home Assistant add-on (non-root, Ingress-only UI)
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

## Versions

Releases are tagged `vX.Y.Z` and listed in [CHANGELOG.md](CHANGELOG.md). Tagging triggers the
release workflow: tests → add-on images on GHCR (amd64, aarch64) → GitHub Release. The add-on's
`version` in `oneroof-zigbee/config.yaml` and `oneroof_zigbee.__version__` must match the tag.
