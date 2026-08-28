# Changelog

## [1.8.1] — 2026-08-28

### Fixed
- Coordinator page layout: the cards used the dashboard's multi-column (masonry)
  grid, which split the different-height cards across columns and made them
  overlap. Switched to a responsive auto-fit grid so each card stays whole.

## [1.8.0] — 2026-08-28

### Added — Coordinator page
- New Coordinator tab in the UI: firmware identity (One Roof build vs stock, Z-Stack version,
  build revision), live radio state (IEEE, PAN, extended PAN, channel, NWK frame counter) and a
  keystore sync verdict — PAN, extended PAN, channel, active network key and frame counter each
  checked live against the keystore, with a Re-check button.  This is the same agreement the
  gateway enforces at every startup (a blank or mismatched coordinator is re-formed from the
  keystore), now visible instead of a log line.
- `GET /api/coordinator` serves it: reads the radio on demand (device info, extended network
  info, security material table, active key compare) and answers 503 when the coordinator does
  not respond.
- The fake coordinator's extended-network-info now reports the extended PAN id it was formed
  with instead of zeros, so the sync verdict is honest in tests.


## [1.7.3] — 2026-08-28

### Fixed — empty device list, alert storms
- A single non-serializable value in one device's state (e.g. a raw vendor datapoint delivered as
  bytes) emptied the whole device list with "internal error". State values are now always made
  JSON-safe on ingest (bytes become hex), existing records are healed at start, and one broken
  record can no longer take down the list.
- The sequence-number check understands that devices run several independent counters (Tuya plugs
  interleave time requests and reports): a value near any recent counter is normal, counters only
  move forward, and only a value matching none of them twice in a row is an anomaly. The
  plug "sequence jump" storm was this.
- "Went silent" alerts once per outage and again only after the device has been heard in between —
  a bulb cut from power by a wall switch no longer alerts every 15 minutes for days.

## [1.7.2] — 2026-08-22

### Changed
- Unknown-device alerts and the Pair page list show the vendor derived from the address block
  (e.g. Tuya devices) and point to Pair → Unknown devices to adopt or evict.

## [1.7.1] — 2026-08-22

### Changed
- Activity/Logs rows show the device's name (linked to its page) next to every record that carries
  an address.
- A battery device with known model knowledge that answers one descriptor request and then sleeps is
  considered described ("described by model knowledge") instead of failing its interview forever —
  its features come from the model table anyway. Mains devices and unknown models still report a
  real failure.

## [1.7.0] — 2026-08-22

### Added — Telegram notifications, with a strict outbound policy
- Settings → **Telegram notifications**: bot token and chat id (token stored encrypted, never shown
  or logged again), categories to send — join window, devices, security, anomalies, health,
  liveness — digest interval, quiet hours, optional addresses, a test button and the last sends.
  Security and anomaly events go immediately; routine events are batched; a hard rate limit applies.
- One outbound path only: a guarded HTTPS client with a host allow-list (`api.telegram.org`),
  TLS 1.2+ verified against the system trust store, off until notifications are enabled; every
  attempt — allowed or refused — is listed under Settings → **Outbound connections**, and refusals are
  security alerts. Nothing else leaves the network; SECURITY.md documents exactly what is sent.
- Broker login failures and lockouts are now security records (`auth_failed`, `auth_lockout`), so
  they show in Activity and can be notified.

## [1.6.7] — 2026-08-22

### Added
- Settings → MQTT broker: **Copy CA certificate** puts the broker's CA text on the clipboard, so a
  client outside Home Assistant (One Roof NVR and others) can be given TLS by pasting it into its
  settings — no file transfer; the SHA-256 fingerprint shown next to it lets you compare.

## [1.6.6] — 2026-08-22

### Added — unknown devices on the network can be adopted or evicted
- A device that holds the network key but is not in the device list (typically paired by the
  previous setup without being in its configuration) is now identified by its IEEE address, shown on
  the Pair page under "Unknown devices on the network" with its address, traffic and link quality,
  and can be **adopted** (registered and interviewed) or **evicted** (told to leave). Alerts
  `traffic_from_unknown_device` carry the IEEE and are raised once, then at the 10th/100th/1000th
  frame instead of on every frame; `unknown_device_adopted` / `unknown_device_evicted` are recorded.

## [1.6.5] — 2026-08-22

### Fixed — interviews and bindings on real hardware
- Device-level ZDO responses (node/simple descriptors, active endpoints, bind/unbind) are forwarded by
  this firmware generation only after the host registers for ZDO messages, and then in a generic
  envelope. The gateway now registers at start and converts forwarded responses into the classic
  indications, so interviews complete, bindings succeed and devices report by themselves instead of
  relying on polling. (Management responses such as the neighbour table were unaffected, which is
  why the network checks worked while every interview timed out.)

## [1.6.4] — 2026-08-22

### Changed
- A failed interview is retried on contact at most every 10 minutes (a chatty device used to trigger
  a descriptor request on every frame).
- A device whose model is known and whose values are flowing no longer shows "not interviewed" in
  the State column; the About badge says "descriptors not read yet · retried when the device is
  awake" with the reason on hover. Battery sensors sleep too fast for descriptor requests and work
  fully without them.

## [1.6.3] — 2026-08-22

### Fixed — door sensors showed the opposite state in Apple Home
- In the device descriptions on `bridge/devices`, `contact` now declares `value_on: false`: the
  value is true when the door is *closed*, so the active (open) state is false — the convention the
  previous setup used and that bridges key their polarity on. Home Assistant was already right
  (`door` class template); Apple Home via One Roof Bridge showed open for closed.

## [1.6.2] — 2026-08-22

### Fixed — phantom entities from earlier descriptions
- Entity configs are retained on the broker; when a device's description changes (corrected
  interview, better model knowledge, a definition), configs that no longer apply are now blanked so
  Home Assistant drops the entity (e.g. a door sensor once described as "MQTT Switch"). The first
  announce after this update also sweeps the shapes earlier versions could have left behind.

## [1.6.1] — 2026-08-22

### Changed — the Home Assistant role is a full broker client
- Home Assistant is the hub: its login (shared by One Roof Bridge through the Supervisor) may now
  subscribe to and publish on any topic — its other integrations' discovery topics, the NVR's events —
  with one exception kept on purpose: it cannot publish on the gateway's own device topics, so a
  leaked Home Assistant token cannot forge sensor states; commands (`/set`, `/get`, bridge requests)
  remain allowed. Opening the network stays a control-user privilege.
- ACL gained deny lists with narrower-allow override; add-on DOCS describe the Bridge and NVR setup.

## [1.6.0] — 2026-08-22

### Added — device descriptions for the other One Roof apps
- `<base>/bridge/devices` now carries, for every device, the *exposes* description the previous
  setup published (`ieee_address`, `type`, `supported`, `definition.vendor/model/description/exposes`
  with light/switch/lock/cover/climate composites and binary/numeric/enum features, access bits,
  per-gang endpoints), derived from our own feature format. One Roof Bridge builds its Apple Home
  accessories from it and One Roof NVR reads the same list — both connect through the MQTT service
  the add-on registers with the Supervisor, so no credentials are typed anywhere.

## [1.5.7] — 2026-08-22

### Changed
- The anomaly monitor ignores Basic-cluster chatter (vendor heartbeats, identity reads) for its burst
  and sequence checks; only link quality and last-seen are taken from such frames. Tuya plugs were
  raising `device_anomaly` with their own heartbeat.

## [1.5.6] — 2026-08-22

### Changed
- Sleepy (battery) devices are no longer interviewed at start — they answer only when awake and are
  interviewed on their next report; no more `interview_failed` parade after a restart.
- A ZCL sequence counter restarting near zero is treated as a device reboot, not an impersonation
  signal.

## [1.5.5] — 2026-08-22

### Fixed — values present in the state are always exposed
- Devices imported without cluster information (the previous database did not carry it) produced no
  measurement entities although their state held temperature/humidity/pressure. Three fixes: such
  devices are interviewed again on contact; the model table adds the measurements of the Aqara
  climate sensors explicitly; and, for every model, any state key with a known meaning that has no
  feature becomes a read-only entity — nothing a device reports is lost on the way to Home Assistant.

## [1.5.4] — 2026-08-22

### Added — MQTT 5 Subscription Identifiers
- The broker now supports (and advertises) subscription identifiers: the identifier a client attaches
  to a subscription is echoed in every matching PUBLISH, including retained replays and multiple
  matching subscriptions. Home Assistant's MQTT client requires this and logged a warning.

## [1.5.3] — 2026-08-22

### Fixed — Home Assistant rejected every discovery message
- Discovery payloads carried `device.sw_version: null` for devices whose firmware build is unknown
  (the normal state after an import). Home Assistant validates strictly and dropped the whole message
  (`string value is None … data['device']['sw_version']`), so no entity was ever (re)created from
  our discovery. Null fields are never emitted any more; a test scans every payload of every fixture
  model.

## [1.5.2] — 2026-08-22

### Fixed — imported devices stayed "unavailable" in Home Assistant
- A device imported from a previous setup is offline until heard from; when it then reported, its
  availability was never switched to online, so Home Assistant kept all of its entities unavailable
  while state messages were flowing. Any frame from a device now marks it online and publishes the
  (retained) availability.

## [1.5.1] — 2026-08-22

### Fixed
- Basic-cluster identity fields (application/stack/hardware version, date code, power source) and
  vendor heartbeat attributes (`basic_0xffe2` …) no longer appear as device state, in Activity or in
  Home Assistant; they go to the device record (About tab).

## [1.5.0] — 2026-08-22

### Added — unknown devices handled, and teachable
- **Datapoint inference** for Tuya datapoint devices without a built-in map: the datapoint ids and
  wire types the device actually reports are matched against the conventional layouts of product
  families (thermostats, covers, sensors, smoke/leak/gas/door, presence radars, multi-gang switches,
  lights, sirens, soil sensors). Conservative: only an unambiguous match is used; everything else stays
  a raw `dp_<n>` feature. Inferred features are tagged in the UI.
- **Device definitions you can write yourself**: a "Datapoints" tab on datapoint devices lists every
  datapoint seen with live values and lets you name each one (key, type, scale, unit, inverted,
  device class); a "Type & category" card on About lets you correct a device's kind. Definitions are
  saved per model in `definitions.yaml`, take precedence over the built-in table, apply immediately
  to every device of that model (discovery re-announced, state rebuilt), are included in backups and
  can be exported/imported as YAML. Control users only; recorded in the audit log.
- Raw datapoints are exposed for every datapoint device, so nothing reported is lost before it is
  named.

## [1.4.5] — 2026-08-22

### Fixed — entity identities for common models
- Aqara H1 wall switches (`lumi.switch.b1lc04/b2lc04`, `b1nc01/b2nc01`, `l1acn1/l2acn1`) are wall
  switches, not remotes: `switch_left`/`switch_right` entities are published again with the previous
  identities, plus device temperature, power-outage count and button actions.
- Tuya smoke detectors (`TS0601`, `_TZE200_rccxox8p` and siblings): smoke, battery, battery-low and
  self-test from datapoints.
- Aqara motion sensors no longer get spurious IAS alarm/tamper/battery-low entities; illuminance uses
  the previous layout's `illuminance` object id.

## [1.4.4] — 2026-08-22

### Added — security requirements
- **Network key rotation over the air**: the new key is handed to every device under its own link
  key, then switched; devices stay paired; whoever holds only the old key is locked out. Live progress
  in Settings → Maintenance. "Rotate and re-pair everything" remains for a leaked trust-centre seed.
- **Liveness and anomaly monitor**: per-device behavioural profiles; `device_anomaly` alerts for
  sequence jumps, link-quality swings, commands from devices that only report, bursts, silence after a
  burst, and mains devices that go silent.
- **Pairing exposure bounded**: a plain join window admits one device and closes at once; after a
  pairing without install code the key is rotated automatically within minutes.

### Changed
- Last known link quality shown for every device; silent mains devices polled every 5 minutes so
  models that never report come alive and get bound; imported devices never marked as interviewed
  are interviewed on contact; wider page layout.

## [1.3.10] — 2026-08-22

### Fixed — the imported network really lands on the coordinator
- Verified on hardware and guarded by tests against a simulated firmware that behaves the same:
  the firmware ignores the pre-configured key at formation and its key items are 17 bytes, writable
  only with the stack stopped. Formation and every start now: form → stop → write key items at exact
  length, frame counter (security material table) and trust-centre seed → start → verify key, seed,
  counter → neighbour check (`coordinator hears N neighbour(s)`). Mismatches are repaired, never
  re-formed blindly, and reported (`network_key_mismatch/repaired`, `frame_counter_verified`,
  `no_neighbours_heard`).
- The trust-centre link-key seed from the backup is restored so every device's link key stays valid.
- Secrets never reach the log: key-bearing frames are redacted at DEBUG, generated passwords are not
  printed. Tuya mains devices get the Basic-cluster read that stops their 200 ms reports.

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

### Fixed — broker and Home Assistant integration on a real installation
- Add-on built from its own folder (no downloads at build time; version asserted at build).
- MQTT 5 clients accepted next to 3.1.1; Home Assistant's dialog can stay on its default.
- Home Assistant's existing broker login is adopted automatically for an hour after an import or
  first start; lockouts are per address *and* username so a stale login cannot block a correct one.
- Per-client subscription limit raised to 2048 (Home Assistant subscribes per entity).
- Running version shown in the UI header and the first log line.

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

### Fixed (1.0.1)
- Join window cooldown on a freshly booted host; client-ID takeover count.
