# OneRoof Zigbee — UI HTTP API

Served by `oneroof_zigbee.ui.server` on `127.0.0.1:8099` (standalone) or via
Home Assistant Ingress (add-on). All paths are relative — the page must use
relative URLs (`api/...`, not `/api/...`) because Ingress mounts it under a prefix.

Security:
* Every mutating request must be `POST` with `Content-Type: application/json`
  **and** header `X-OneRoof: 1` (blocks cross-site form posts).
* Standalone: bound to loopback only. Ingress: only requests from the
  supervisor proxy (172.30.32.2) are accepted.
* The UI acts as the configured `ui.acts_as` MQTT user; control actions
  (permit_join, remove, rotate) succeed only if that user is in `control_users`
  — otherwise 403 `{"ok": false, "error": "not authorized"}`. Every action is
  audit-logged with `by: "ui:<acts_as>"`.
* Responses are `application/json; charset=utf-8`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, CSP `default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:`.

## GET

| Path | Returns |
|---|---|
| `/` | the single-page UI |
| `api/bridge` | `{version, coordinator_ieee, channel, pan_id, strict_install_codes, device_count, permit_join: {open, seconds_left, requested_by}, uptime_s, ui_user, ui_can_control}` |
| `api/devices` | `[{ieee, friendly_name, manufacturer, model, sw_build, power_source, is_router, interviewed, available, lqi, last_seen, endpoints: {"1": {category, in_clusters:[int], out_clusters:[int]}}, state: {...}}]` |
| `api/devices/<ieee>` | one device (same shape) |
| `api/audit?n=200&level=all\|security` | `[{ts, level, type, ...fields}]` newest last (reads tail of audit.log) |
| `api/audit/verify` | `{ok: bool, first_bad_line: int}` |
| `api/logs?n=500` | `[{ts, level, logger, msg}]` in-memory ring buffer of the application log |
| `api/map` | `{nodes: [{ieee, friendly_name, type: "coordinator"\|"router"\|"end_device", lqi}], links: [{source, target, lqi, depth, relationship}]}` — cached; refreshed by `POST api/map/refresh` |
| `api/events` | **SSE stream**: `event: state` `data: {ieee, state}`, `event: audit` `data: {...}`, `event: security`, `event: device` (`{action: "joined"\|"left"\|"interviewed"\|"renamed", device}`), `event: permit_join` `data: {open, seconds_left}`, `event: log` `data: {ts, level, logger, msg}` |

## POST (JSON body)

| Path | Body | Effect |
|---|---|---|
| `GET api/unknown` | — | unregistered devices heard on the network `{devices:[{ieee,nwk,frames,clusters,lqi,first_seen,last_seen}]}` |
| `POST api/unknown/<ieee>/adopt` / `…/evict` | `{}` | control-only; register+interview, or send a leave request |
| `api/permit_join` | `{seconds: 60, ieee?: "0x…", install_code?: "…"}` | open window (seconds 0 = close). Returns `{ok, seconds?, error?}` |
| `api/devices/<ieee>/set` | any device command, e.g. `{state:"ON", brightness: 200}` | same as MQTT `set` |
| `api/devices/<ieee>/rename` | `{friendly_name}` | |
| `api/devices/<ieee>/remove` | `{}` | control-only |
| `api/devices/<ieee>/interview` | `{}` | |
| `api/devices/<ieee>/identify` | `{}` | identify 10 s |
| `api/map/refresh` | `{}` | walks neighbour tables of coordinator + routers (takes seconds) |
| `api/rotate_network_key` | `{mode: "over_the_air", window_s: 300}` (default) → `{rotation: {phase, delivered[], failed{}, switch_at, seconds_left}}`; or `{mode: "repair", confirm: "I understand all devices must be re-paired"}` → `{restart_required: true}` | control-only |
| `GET api/rotate_network_key` | — | rotation status `{phase: idle\|delivering\|waiting\|switching\|done\|failed, …}` |
| `api/settings` | `{log_level?: "DEBUG"}` | runtime-only settings |

Errors: `{ok: false, error: "..."}` with 400/403/404/500.

## Device detail (v0.2)

`GET api/devices/<ieee>` now returns, in addition to the list shape:

```
description: str|null,
nwk: "0x98c3", nwk_decimal: 39107,
oui_vendor: "Telink Semiconductor (Taipei) Co. Ltd." | null,     # from embedded OUI table
manufacturer_code: int|null, power_source: "mains"|"battery"|..., 
sw_build, hw_version, date_code, zcl_version, app_version, stack_version,
joined_at, last_seen, interviewed, interview_error: str|null,
mqtt: {state_topic, set_topic, availability_topic},
endpoints: {"1": {category, profile, device_id, device_type, in_clusters:[{id,name}], out_clusters:[{id,name}]}},
exposes: [Feature],            # generic, derived from clusters (below)
activity: [{ts, key, old, new}],   # last 50 state changes, newest last
reporting: [{endpoint, cluster, cluster_name, attribute, attribute_name, min, max, change, status}],
bindings:  [{endpoint, cluster, cluster_name, target: "coordinator"|"0x…", target_endpoint}],
raw: {"<cluster_id>": {"<attr_id>": {name, value, ts}}}    # last raw attribute values seen
```

`Feature`:
```
{ key: "state", name: "State", description: "On/off state of the switch", icon: "power",
  type: "binary"|"numeric"|"enum"|"composite"|"action"|"text",
  access: "r"|"rw"|"w", unit?: "W", min?, max?, step?, values?: [...], value_on?: "ON", value_off?: "OFF",
  endpoint: 1, cluster: 6, category: "control"|"sensor"|"config"|"diagnostic" }
```
Generic features generated per cluster: on_off → `state` (+ `power_on_behavior` enum off/on/toggle/previous from StartUpOnOff 0x4003, + `countdown` action seconds via OnWithTimedOff), level → `brightness`, color → `color_temp`/`color_xy`, electrical/metering → power/current/voltage/energy, sensors, battery, covers `position`, thermostat `heating_setpoint` + `system_mode`, always `identify` action and `linkquality` diagnostic.

New POST routes (all JSON + `X-OneRoof: 1`):

| Path | Body | Effect |
|---|---|---|
| `api/devices/<ieee>/describe` | `{description}` | set free-text description (≤ 200 chars) |
| `api/devices/<ieee>/set` | `{power_on_behavior: "previous"}` / `{countdown: 30}` / existing keys | writes StartUpOnOff / sends OnWithTimedOff |
| `api/devices/<ieee>/read` | `{endpoint, cluster, attributes:[int]}` | live Read Attributes; returns `{ok, values:{attr_id: value}, decoded:{...}}` and updates state |
| `api/devices/<ieee>/reporting` | `{endpoint, cluster, attribute, min, max, change}` | (re)configure reporting; returns status |
| `api/devices/<ieee>/bind` | `{endpoint, cluster, target: "coordinator"\|"0x…", target_endpoint?}` | ZDO bind; `unbind` with same body on `api/devices/<ieee>/unbind` |

SSE: `event: activity` `data: {ieee, ts, key, old, new}` on every state change.

## Settings / administration (v0.3)

All POSTs here are **control-only** (403 otherwise). `api/bridge` now also carries `restart_required: [keys]` and `managed: bool`.

| Path | Returns / Body |
|---|---|
| `GET api/config` | `{managed, config_path, restart_required:[..], config:{serial:{port,baudrate,rtscts}, zigbee:{channel,strict_install_codes,permit_join_max_seconds,permit_join_require_install_code,permit_join_cooldown_seconds}, mqtt:{listen,port,base_topic,tls:{mode:"auto"\|"custom"\|"off",cert,key,client_ca,hostnames:[]}}, homeassistant:{discovery,discovery_prefix}, ui:{enabled,listen,port,acts_as}, log_level}, serial_ports:[paths], tls:{mode,enabled,ca_path?,ca_fingerprint_sha256?}, coordinator:{ieee,version:{product,major,minor,maint,revision}\|null,channel,pan_id}, roles:{name:{description,control}}, ha_setup:{host,port,tls,user,base_topic,discovery_prefix}, data_dir}` |
| `POST api/config` | body = partial `config` (same shape, only changed sections/keys) → `{ok, changed:[keys], restart_required:[keys]}`; 400 with message on invalid; 403 when `managed` (then show "change in the add-on configuration") |
| `GET api/users` | `{users:[{name, role, source:"gateway"\|"config"\|"ui"\|"password-only", has_password, control, subscribe:[..], publish:[..], editable}], gateway_user}` |
| `POST api/users` | `{name, role:"homeassistant"\|"admin"\|"readonly"\|"custom", password?, control?, subscribe?, publish?}` (password ≥ 12 chars; required for new users; custom role uses subscribe/publish) → `{ok, users}` — applied live, no restart |
| `POST api/users/<name>/remove` | `{}` → `{ok, users}` |
| `GET api/tls/ca` | the CA certificate (PEM download) — 404 when tls mode ≠ auto |
| `POST api/backup` | `{password}` (≥ 12) → `{ok, filename, data_b64}` — the UI turns data_b64 into a Blob download |
| `POST api/restore` | `{password, data_b64}` → `{ok, restored:[files], restart_required}` |
| `POST api/restart` | `{}` → `{ok}`; the process restarts (SSE drops, UI should show "restarting…" and poll `api/bridge` until it answers again) |
| `POST api/settings` | `{log_level}` runtime only (existing) |

## v0.3.1 additions
* `api/config` → `config.serial` gains `adapter` ("zstack", read-only) and `is_network`; `config.mqtt` gains `plaintext_port` (int|null); response gains `defaults` = `{section: {key: default}}` for "Reset to defaults".
* `POST api/config` accepts `mqtt.plaintext_port` (null to disable) and `serial.port` values of the form `tcp://host:port`.
* `mqtt.tls.client_ca` is valid in **every** TLS mode (auto or custom): when set, clients must present a certificate signed by it (mTLS) ("require client certificate").

## v0.4 — Dashboard, Activity, Firmware, Import

| Path | Returns / Body |
|---|---|
| `GET api/activity?device=<ieee or name>&key=<state key>&n=200` | `{rows:[{ts, ieee, friendly_name, key, old, new}] newest last, keys:[all keys seen]}` — state-change feed across ALL devices (distinct from the audit log, which records actions). SSE `activity` events carry `{ieee, ts, key, old, new}`. |
| `GET api/firmware` | `{images:[{file, manufacturer, image_type, file_version, file_version_decimal, stack_version, header_string, size, sha256}], allow_downgrade, policy}` |
| `POST api/firmware/upload` | `{filename, data_b64}` (control-only; the file is parsed and verified; 400 with reason) → `{ok, image}` |
| `POST api/firmware/<file>/remove` | `{}` (control-only) |
| `GET api/devices/<ieee>/update` | `{has_ota_client, armed: file|null, last_query: {ts, manufacturer, image_type, file_version, hw_version}|null, session: {file, progress(0-100), offset, total, finished, result, started, last_activity}|null, candidates:[images matching the device's last query]}` |
| `POST api/devices/<ieee>/update/check` | `{}` → asks the device to report its firmware (it answers within seconds; poll `update` or watch audit). Works only if `has_ota_client`. |
| `POST api/devices/<ieee>/update/start` | `{file}` (control-only) → arms the image for this device and notifies it; 400 if manufacturer/type mismatch or not newer |
| `POST api/devices/<ieee>/update/cancel` | `{}` (control-only) |
| `POST api/import/preview` | `{ "configuration.yaml"?: text, "database.db"?: text, "coordinator_backup.json"?: text }` (control-only) → `{ok, network:{found, source, channel, pan_id, ext_pan_id, frame_counter, key_is_well_known_default, coordinator_ieee}, devices:[{ieee, friendly_name, model, manufacturer, router, endpoints, interviewed}], warnings:[..]}` |
| `POST api/import/apply` | same body → `{ok, devices, network_adopted, summary, restart_required}` — devices appear immediately; a restart is needed when the network was adopted |

Dashboard data: use `GET api/devices` (list shape includes `state`, `endpoints[].category`, `lqi`, `available`) and per-device `exposes` from `GET api/devices/<ieee>` (cache per device; features don't change unless re-interviewed).

## v0.5 — legacy layout on import
* `POST api/import/preview` response gains `mqtt: {server, user, has_password, base_topic, homeassistant_prefix, homeassistant_enabled}` read from the previous setup's configuration.yaml.
* `POST api/import/apply` accepts `keep_broker` (default true: keep using the previous setup's broker, written as `mqtt.external`), `keep_entities` (default true: `compat.legacy_layout` + same base topic + discovery prefix, so Home Assistant entities/topics stay identical), `broker_user` / `broker_password` (required when the add-on got its broker login from the Supervisor and configuration.yaml has none). Response gains `compat: [changed keys]`.
* `GET api/config` → `config.compat.legacy_layout` (bool) and `config.external` (`{server,user,has_password,ca}` or null). `POST api/config` accepts `compat.legacy_layout` and `mqtt.external` (object, or null to switch back to the built-in broker).
* `api/bridge` / device `mqtt` block include `legacy_layout`.

## v0.6 — server-side import
* `GET api/import/scan` → `{folders:[{path, files:{"configuration.yaml":bool,"database.db":bool,"coordinator_backup.json":bool,"state.json":bool}}], roots:[..]}` — previous-setup folders found under the allowed import locations (in the add-on: the read-only Home Assistant config share, e.g. `/homeassistant/zigbee2mqtt`).
* `POST api/import/preview` and `POST api/import/apply` accept `{"folder": "<path from scan>"}` instead of file contents; the server reads the files itself (403 if the folder is outside the allowed locations).
* Uploads additionally accept a `"state.json"` key.

## Notifications and outbound connections

| Path | Returns / Body |
|---|---|
| `GET api/notify` | `{settings:{enabled, categories:{join_window,devices,security,anomalies,health,liveness}, digest_seconds, include_addresses, quiet_start, quiet_end}, has_token, chat_id, categories:{name: description}, sent, failed, dropped, queued, recent:[{ts, ok, lines, chars, test, preview|error}] (last 20), egress:{enabled, allowed_hosts, hosts}}` — the bot token is never returned |
| `PUT api/notify` | partial settings (same keys as `settings`) plus optional `bot_token` and `chat_id` — both are stored only when present and non-empty (control-only) → `{ok, changed:[keys], …status}`; 400 with a message on invalid values. Applied live, no restart. Audited as `notify_settings_changed` (key names only). |
| `POST api/notify/test` | `{}` (control-only) → `{ok, recent:[…]}`; 400 when disabled or no token/chat id, 502 when Telegram refused |
| `DELETE api/notify/token` | (control-only) removes the stored bot token → `{ok, …status}` |
| `GET api/egress` | `{enabled, allowed_hosts:[…], hosts:{host:{count, last, refused, last_error}}, policy}` — the ledger of every outbound attempt |
