# Changelog

All notable changes to OneRoof Zigbee. Versions follow [Semantic Versioning](https://semver.org):
MAJOR = breaking (re-pairing or config migration needed), MINOR = features, PATCH = fixes.

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
  import from zigbee2mqtt, firmware library, maintenance (log level, restart, key rotation).
- OneRoof design system (shared with OneRoof Bridge), light/dark, phone layout.

### Migration
- Import from zigbee2mqtt (`configuration.yaml`, `database.db`, `coordinator_backup.json`) without re-pairing
  when keeping the same dongle; frame-counter restore when re-forming; UI and CLI (`import-z2m`).

### Firmware (OTA)
- Local-only OTA server: uploaded images are parsed and verified (manufacturer, image type, version, size,
  SHA-256) and offered only to a matching device, only when newer, only on explicit user action.

### Security & operations
- AES-256-GCM keystore, 0600 files, SHA-256 hash-chained audit log with verification, security alerts on MQTT,
  encrypted backups, restart from the UI, `passwd` / `pair` / `verify-audit` / `import-z2m` CLI.

### Tests
- 279 tests: byte-exact codecs, coordinator bring-up against a scripted ZNP, broker, UI API, and an end-to-end
  suite that boots the production entry point with simulated devices over real TLS MQTT/HTTP plus a
  real-browser suite. CI on Python 3.11–3.13.

### Known limitations
- Not yet validated on physical hardware.
- No Tuya/Aqara private clusters, groups/scenes, Silicon Labs (EZSP) coordinators, or touchlink.
