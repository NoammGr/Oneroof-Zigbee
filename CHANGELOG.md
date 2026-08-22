# Changelog

## [1.3.10] — 2026-08-22

### Changed — the restore is now the normal path, and secrets stay out of the log
- Importing a previous setup and starting the coordinator always goes through the sequence that
  proved to work on hardware: network formed, then — with the stack stopped — key items written at
  their exact length, frame counter table and trust-centre seed written, then started and verified
  (key, seed, counter, and the neighbour check). The simulated firmware in the tests now behaves
  like the real one (ignores the pre-configured key, 17-byte key items) and an end-to-end restore
  test guards it.
- The add-on never prints a generated password any more (Home Assistant receives it through the
  Supervisor; set your own in Settings → Users & access), and the start-up banner no longer shows
  manual MQTT instructions.
- Devices show their last known link quality (kept across restarts and seeded from the imported
  state) instead of "—" until they next report.
- Tuya mains devices (`_TZ…`) get the one Basic-cluster read after which they stop reporting every
  200 ms, at configuration and once per start on their first frame.

## [1.3.9] — 2026-08-22

### Fixed
- Key items are written with exactly their own length (the counter part is absent on firmware that
  keeps counters in the security material table; a longer write was refused). The item length is
  logged.
- The ZDO network-key update is also tried in its broadcast form when the self-addressed form is
  refused; it installs the key locally as well, and the broadcast is encrypted under the current key.

## [1.3.8] — 2026-08-22

### Fixed — Home Assistant denied everything right after a restart
- Users managed in the web UI (and their role permissions) were loaded into the broker's access list
  only after the coordinator had started, ~10 s after the broker opened its port. Home Assistant
  reconnects within a second, subscribes once and keeps the denials (`acl: user 'homeassistant'
  denied subscribe …`). Users are now loaded before the broker accepts any client.

## [1.3.7] — 2026-08-22

### Fixed — the imported key is installed through the network-key update
- On firmware whose key items are read-only (confirmed: writes refused even with the stack stopped,
  and 0 neighbours heard), the imported key is now installed with the ZDO network-key update/switch
  commands addressed to the coordinator itself — the mechanism Zigbee uses for key rotation, nothing
  is sent over the air. The devices' key sequence number is kept. Result is logged and recorded
  (`network_key_repaired method=zdo`); the neighbour check 45 s later confirms it.

## [1.3.6] — 2026-08-22

### Fixed — key material is written the way the firmware accepts it
- Key items, the frame counter and the trust-centre seed are now written into the coordinator
  **while the stack is stopped** — right after a reset and before the network is started — both when
  the network is formed for an imported setup and when a repair is needed. Writes while the network
  runs are refused by the firmware; that is why earlier repairs did not take.

## [1.3.5] — 2026-08-22

### Fixed
- The frame counter is read from the right extended-NV table (0x0007; 0x0001 is the address manager,
  whose entries were misread as counters).
- A key-item mismatch no longer re-forms the network at every start (destructive, and it did not
  change the verdict on hardware); it is reported and left to the neighbour check.

### Added — neighbour check
- 45 s after start the coordinator's neighbour table is read and logged (`coordinator hears N
  neighbour(s), M router(s)`), recorded as `neighbour_check`; an empty table raises
  `no_neighbours_heard`. Routers announce themselves under the network key, so this is the ground
  truth for "is the key right and is anyone in range".

## [1.3.4] — 2026-08-22

### Fixed — frame counter read and written where this firmware keeps it
- On Z-Stack 3.x.0 the live NWK frame counter is kept in the security material table (extended NV
  API), not in the legacy key item. The gateway now reads the counter from there (entry for our
  extended PAN id, else the generic entry) and, when the SET command is not kept, writes it there
  before restarting the network. Routers drop frames from a coordinator whose counter is below the
  one they remember, which looks exactly like a wrong key.

## [1.3.3] — 2026-08-22

### Fixed — the network is formed on the keystore key
- Confirmed on hardware: the firmware only takes `PRECFGKEY` as the network key when
  `PRECFGKEYS_ENABLE` is 1 during formation; with 0 it made up a key of its own, so an imported
  network was formed on the wrong key and no router ever answered. Formation now enables it for the
  formation step only and switches it back to 0 afterwards (joining devices still receive the key
  under a link key, never assume it).
- A refused direct write to the key items (status 0x02) no longer crashes the gateway: the network is
  re-formed on the keystore key instead and verified; a refused frame-counter write raises
  `frame_counter_unverified` instead of failing the start.

## [1.3.2] — 2026-08-22

### Fixed — the radio's active key is repaired, not just reported
- If the key the radio actually uses differs from the keystore's (some firmware variants form the
  network on a key of their own unless the key items are written explicitly), the active, alternate
  and legacy key items are rewritten with the imported key — keeping the frame counter — the network
  is restarted and the key verified again (`network_key_repaired`). "No route" to every router
  (`AF … 0xcd`) was the visible symptom.

## [1.3.1] — 2026-08-22

### Fixed — imported network: link-key seed restored, key verified
- The previous setup's backup carries the trust-centre link-key seed the devices' individual link
  keys were derived from; the import now keeps it and the coordinator is given it when the network is
  formed (or at the next start if missing), so every device's link key stays valid.
- At start the gateway checks that the key the radio actually uses equals the keystore's and that the
  seed matches (`active network key … matches: yes/NO`, never printing either); a mismatch raises a
  `network_key_mismatch` alert.

## [1.3.0] — 2026-08-22

### Added — device knowledge: models, vendors, private protocols
- A declarative model table (206 entries, 768 model patterns) tells the gateway what a device *is*:
  Aqara/Xiaomi, Tuya (incl. the TS0601 datapoint protocol for temperature/humidity sensors, TRVs,
  wall thermostats, curtains, blinds and presence radars), IKEA, Philips Hue, Sonoff/eWeLink, Heiman,
  frient/Develco, Schneider, Legrand/Netatmo, Bosch, Danfoss, Eurotronic, Innr, OSRAM/LEDVANCE,
  SmartThings/Samjin/Centralite, Third Reality, Ubisys, Gledopto, Paulmann, Müller Licht, Linkind,
  Namron, Sunricher, Aurora, Visonic, Sercomm, Xfinity, LiXee, Moes, Lidl, Yale/Schlage/Kwikset locks.
- Each device now has a kind ("Contact sensor", "Smart plug", "Wall switch (2 gang)" …), vendor and
  category, shown in the Devices table and About tab; sensors are read-only, plug-only controls no
  longer appear on sensors, remotes and buttons publish `action`, multi-gang switches get one control
  per gang, locks/covers/thermostats have proper controls.
- Vendor reports decoded: Aqara private attributes (battery voltage and %, device temperature, power
  outage count, illuminance, power/energy), Tuya datapoints (reports and writes).
- Home Assistant discovery derives device classes and units from the features (door, motion, moisture,
  smoke, CO, gas, vibration, tamper, battery, voltage, device temperature, VOC/CO₂/PM2.5 …), adds
  select/number/lock/cover/climate entities, and keeps the legacy object ids so imported entities
  survive unchanged.
- Clusters added: scenes, analog/multistate/binary input, poll control, door lock, pump, fan, CO₂,
  PM2.5, diagnostics, Tuya and vendor-specific clusters.

## [1.2.21] — 2026-08-21

### Fixed
- Per-client subscription limit raised from 64 to 2048: Home Assistant subscribes to one topic per
  entity plus its discovery filters and was being cut off (`subscription limit reached`), leaving
  entities without updates.

## [1.2.20] — 2026-08-21

### Fixed — devices ignored the coordinator after an import
- The coordinator's NWK frame counter is now read back after every start. If it is below the
  imported value, it is set again with the network up and verified; if the firmware still does not
  keep it, the active/alternate key items are written directly and the network restarted. The log
  states the counter found and the result; Activity records `frame_counter_verified` or a
  `frame_counter_unverified` alert. Devices drop every frame from a coordinator whose counter is
  lower than the last one they saw — which looked like "no answer, no state, no LQI".

## [1.2.19] — 2026-08-21

### Fixed — Home Assistant could lock itself out
- The login lockout is now per address **and username**. Everything inside Home Assistant arrives
  from one address, so a stored login that kept failing (after a user was removed or its password
  changed) locked that address and rejected a correct login typed into the MQTT dialog as well.

## [1.2.18] — 2026-08-21

### Changed
- Imported devices whose address is known from the backup are interviewed directly after start
  instead of waiting for an answer to a broadcast address query (which some devices never give).
  A failed direct interview is retried when the device next talks.

## [1.2.17] — 2026-08-21

### Added — Home Assistant's existing broker login is adopted
- For one hour after an import (or the first start), the add-on adopts the login Home Assistant's MQTT
  integration keeps sending from its own address inside the add-on network: the user is created with
  the Home Assistant role, the window closes, and `broker_login_adopted` is recorded. No dialog, no
  typing — the migration is fully automatic. Details and limits in SECURITY.md.

## [1.2.16] — 2026-08-21

### Added — MQTT 5 clients
- The broker accepts MQTT 5 connections next to 3.1.1: properties in every packet are parsed and
  validated, reason codes are used in CONNACK/SUBACK/UNSUBACK/DISCONNECT, session expiry 0 is treated as a
  clean session, "retain handling = never" is honoured, a taken-over session is told why. The broker
  advertises QoS 1, retained messages and wildcards, and no topic aliases or shared subscriptions.
  Home Assistant's MQTT integration can be left on its default protocol setting.

## [1.2.15] — 2026-08-21

### Fixed — Home Assistant kept the previous broker's login
- Home Assistant adopts an announced broker only when no MQTT integration exists yet; with an existing
  one it keeps the previous login (`addons`) and fails to connect every few seconds. The broker now logs
  a one-time instruction when it sees that login, and README/DOCS describe the one-time reconfiguration.
- Changing the Home Assistant user's password in the web UI also updates the login the add-on announces
  to Home Assistant on every start.

## [1.2.14] — 2026-08-21

### Changed — deterministic builds, clear versions, clean logs
- The gateway package lives inside the add-on folder and is copied into the image at build time; nothing
  is downloaded during the build, and the build fails if the packaged version and the add-on version
  disagree. The image always contains exactly the version the add-on store shows.
- The running version is shown at the top right of every page and in the first log line at start.
- The byte-level DEBUG log of coordinator traffic redacts frames that carry keys (network key, link keys,
  trust-centre key, install codes), so a pasted log never gives away the network.
- After start, the PAN id and channel the radio reports are compared with the keystore; a mismatch (the
  firmware kept a previous network) is logged and raised as a `network_parameters_mismatch` alert, so a
  key rotation that did not take effect cannot go unnoticed.
- Repository tidied: build artefacts removed from version control, `config.example.yaml` under `docs/`,
  the test runner under `tests/`; add-on README brought up to date.

## [1.2.9] — 2026-08-21

### Added — import straight from the Home Assistant share, complete and safe
- The import card shows "Found on this Home Assistant": the previous setup's folder is read by the add-on
  itself (read-only) — one click, no uploads. Uploads remain as a fallback (now with a `state.json` slot),
  and a file the browser cannot read is reported instead of sent half-empty.
- `coordinator_backup.json`'s device table supplies every device's short address, so imported devices are
  addressable immediately; devices without an address are looked up by a ZDO broadcast after start and
  interviewed as soon as they answer; sleepy ones are picked up on their next report.
- An interview never targets short address 0 (the coordinator itself); data recorded that way is discarded.
- `ext_pan_id` lists in `configuration.yaml` are read in the right byte order, so the coordinator's stored
  settings match the imported ones and the network is started, not re-formed.
- A restored frame counter is set well above the saved value; mismatching coordinator settings are named in
  the log (`coordinator_nv_mismatch`).

## [1.2.5] — 2026-08-21

### Added — automatic handover of Home Assistant's MQTT, first run on real hardware
- The add-on registers itself as Home Assistant's MQTT service (`services: mqtt:provide`): the MQTT
  integration and add-ons that auto-detect the broker switch to One Roof Zigbee by themselves. Importing a
  previous setup in the add-on enables the legacy layout automatically and recreates the previous broker
  login (new `client` role) so clients outside Home Assistant keep connecting.
- Plain MQTT listener (1883) inside the add-on network by default (needed by Home Assistant's discovery);
  no host ports unless enabled.

### Fixed
- Least privilege done automatically: the add-on starts as root only to read the Supervisor's options and
  own its config folder, proves the coordinator is usable by uid 1000 (opening the device exactly as
  configured) and drops root when it is; otherwise it stays root like other add-ons and says so.
- `APP_CNF_BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY` mode byte encoded correctly (the firmware rejected the
  old encoding with INVALID_PARAMETER, aborting network formation on a Sonoff ZBDongle-P).
- The web UI is shipped as package data ("UI not built").

## [1.1.13] — 2026-08-21

### Added — Home Assistant add-on store
- Repository laid out as a Home Assistant add-on repository (`repository.yaml`, `oneroof-zigbee/` at the
  root) under "One Roof Zigbee Add-ons", with the family icon, logo, `DOCS.md` and the changelog link.
- Release pipeline: CI (lint + tests on 3.11–3.13), Auto-tag on push to `main`, release workflow that
  verifies versions, builds add-on images (amd64, aarch64) and publishes a GitHub Release.

### Fixed — everything found bringing the add-on up on a real Home Assistant
- Store visibility: `serial_port` has no default (the Supervisor rejects a non-existent default device);
  the add-on `config.yaml` is committed (a `.gitignore` rule had excluded it).
- Build on the Supervisor's Alpine base (Python and compiled dependencies from Alpine packages).
- No host ports claimed by default (an existing broker add-on usually owns 8883/1883).
- Config folder mounted at `/config` (the Supervisor owns `/data`); root-owned `options.json` readable.
- `network_coordinator` accepts `host:port` or `tcp://host:port`; unreadable coordinators and missing
  broker logins are reported as one clear instruction.
- Test suite robust on CI (MQTT delivery waits, container-safe Chrome launch with skip).

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
