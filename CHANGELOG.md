# Changelog

All notable changes to OneRoof Zigbee. Versions follow [Semantic Versioning](https://semver.org):
MAJOR = breaking (re-pairing or config migration needed), MINOR = features, PATCH = fixes.

## [1.1.5] — 2026-08-21

### Fixed
- End-to-end tests: wait for MQTT delivery of state/availability instead of reading immediately after the
  interview flag flips; the assertion could run a few milliseconds early on slower CI runners. No product
  change.

## [1.1.4] — 2026-08-21

### Changed
- Own Zigbee mark for the add-on icon, logo and the web UI favicon: a stylised "Z" with a radio arc on the
  One Roof orange tile (an original glyph, not the trademarked Zigbee logo).

## [1.1.3] — 2026-08-21

### Changed — add-on page like the rest of the family
- Add-on logo now reads "One Roof Zigbee" (same house mark and lockup as One Roof Bridge).
- `CHANGELOG.md` ships inside the add-on folder, so the add-on page shows the "(Changelog)" link. The
  release workflow checks it matches the repository changelog.

## [1.1.2] — 2026-08-21

### Fixed — add-on still not appearing in the store
- The add-on's `config.yaml` had never reached the repository: the `.gitignore` rule for the standalone
  `config.yaml` also matched `oneroof-zigbee/config.yaml`. The rule is now anchored to the repository root
  and the add-on config is committed. Without it the Supervisor cannot see an add-on at all.

## [1.1.1] — 2026-08-21

### Fixed — add-on not appearing in the Home Assistant store
- `serial_port` no longer has a default value. The Supervisor's `device()` validator rejects a default
  path that does not exist on the host (e.g. `/dev/ttyUSB0` when the adapter is under `/dev/serial/by-id/`),
  which could keep the add-on from loading at all. The port is picked from the dropdown; if neither a
  serial port nor a network coordinator is set, the add-on stops with a clear message instead of crashing.

### Changed — store presentation
- Repository name "One Roof Zigbee Add-ons" and add-on name "One Roof Zigbee", the family icon and logo,
  and a `DOCS.md` for the add-on's Documentation tab — so it sits next to "One Roof Bridge Add-ons" in
  the store as a sibling.

## [1.1.0] — 2026-08-21

### Added — seamless migration from a previous setup
- **Legacy layout** (`compat.legacy_layout`): the previous setup's topics `<base>/<friendly name>`, availability
  payloads and Home Assistant discovery `unique_id`s / device identifiers, so HA
  keeps the same entities (ids, names, areas, history, automations, dashboards) and other MQTT consumers keep
  their subscriptions. Supports `<base>/<name>/get` state refresh requests.
- **Existing broker mode** (`mqtt.external`): the gateway connects to an existing broker instead of starting
  its own. MQTT control requests are refused in this mode (no authenticated
  publisher); pairing stays in the UI.
- The importer reads the previous setup's `mqtt:` section (server, login, base topic, discovery prefix); the import
  UI offers "Keep using my current MQTT broker" and "Keep Home Assistant entities and topics identical"
  (both default on). Settings → MQTT broker shows the active mode with one-click "Switch to the built-in TLS
  broker" and a compat toggle.
- Add-on: `legacy_layout`, `external_broker*`, `base_topic` options; with `services: mqtt:want` the existing
  broker login is obtained from the Supervisor automatically.

- Import also reads `state.json` (last known states) so dashboards are populated before devices report;
  devices imported without `database.db` get a full interview on first contact.
- Unknown short addresses are resolved with a ZDO IEEE lookup (rate-limited) before being treated as
  unknown devices, so imported or re-addressed devices are recognised.

### Changed
- Repository layout follows Home Assistant's add-on repository format: `repository.yaml` and the
  `oneroof-zigbee/` add-on folder at the root. The add-on builds from the folder alone (installs the gateway
  from this repository's release tarball), so it works both built locally by the Supervisor and from GHCR.

### Tests
- End-to-end scenario with a stand-in existing broker and an already-subscribed Home Assistant: identical topics,
  identical discovery identities, control via the old `/set` topic, network still not openable over MQTT.

## [1.0.1] — 2026-08-21

### Fixed
- Join window could be refused with "cooldown" on a freshly booted host (the cooldown compared against
  a never-set close time; `monotonic()` is uptime on Linux). Found by CI running in a young container.
- MQTT client-ID takeover: the superseded session stayed in the client count until its task unwound.

## [1.0.0] — 2026-08-21

First release. Zigbee gateway and MQTT broker in one process, written from scratch, security first.

### Radio / coordinator
- TI Z-Stack 3.x (CC2652/CC1352) over USB or `tcp://` network coordinators; own UNPI/ZNP driver.
- Random network key, PAN and extended PAN per install; `TC_REQUIRE_KEY_EXCHANGE`, no public-key rejoin.
- Join window capped (default 120 s), auto-closing, with cooldown; install-code pairing (AES-MMO verified
  against the Zigbee test vector); optional strict mode (public ZigBeeAlliance09 key disabled).
- Unexpected joins evicted and alerted; imported/known devices recognised as rejoins.
- Interview, bind + attribute reporting, IAS zone enrolment, tolerant ZCL decoding.

### Devices (standard ZCL, no per-model database)
- Lights (on/off, level, colour xy, colour temperature), plugs (on/off, power, current, voltage, energy),
  temperature/humidity/pressure/illuminance/occupancy, IAS contact/motion/leak/smoke/CO/vibration,
  battery, window coverings, thermostats; power-on behaviour (StartUpOnOff) and countdown (OnWithTimedOff).

### Broker
- Own MQTT 3.1.1 broker: users with scrypt passwords, roles (Home Assistant / Admin / Read-only / Custom ACL),
  `control_users` gate for pairing/removal/key rotation, 5-attempt lockout, connection and retained-store caps.
- TLS 1.2+ on by default with a generated local CA (`tls/ca.crt`), optional mTLS, optional legacy plaintext port.

### Home Assistant
- MQTT discovery for all entities; bridge entities (permit join switch, last security alert, device count).
- Add-on: non-root, no privileged APIs, UI only through Ingress, read-only view of the HA config for imports.

### Web UI (single self-contained file, no external requests)
- Dashboard, Devices with detail tabs (About, Controls, State, Clusters, Reporting, Bind, Firmware), Pair,
  Network map, Logs (audit + application), Activity feed, Settings admin console with help on every setting:
  coordinator, Zigbee security, MQTT/TLS, users & access, Home Assistant, backup/restore (encrypted),
  import of a previous setup, firmware library, maintenance (log level, restart, key rotation).
- OneRoof design system (shared with OneRoof Bridge), light/dark, phone layout.

### Migration
- Import of a previous setup (`configuration.yaml`, `database.db`, `coordinator_backup.json`) without re-pairing
  when keeping the same dongle; frame-counter restore when re-forming; UI and CLI (`import`).

### Firmware (OTA)
- Local-only OTA server: uploaded images are parsed and verified (manufacturer, image type, version, size,
  SHA-256) and offered only to a matching device, only when newer, only on explicit user action.

### Security & operations
- AES-256-GCM keystore, 0600 files, SHA-256 hash-chained audit log with verification, security alerts on MQTT,
  encrypted backups, restart from the UI, `passwd` / `pair` / `verify-audit` / `import` CLI.

### Tests
- 279 tests: byte-exact codecs, coordinator bring-up against a scripted ZNP, broker, UI API, and an end-to-end
  suite that boots the production entry point with simulated devices over real TLS MQTT/HTTP plus a
  real-browser suite. CI on Python 3.11–3.13.

### Known limitations
- Not yet validated on physical hardware.
- No Tuya/Aqara private clusters, groups/scenes, Silicon Labs (EZSP) coordinators, or touchlink.
