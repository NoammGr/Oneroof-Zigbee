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
| `api/permit_join` | `{seconds: 60, ieee?: "0x…", install_code?: "…"}` | open window (seconds 0 = close). Returns `{ok, seconds?, error?}` |
| `api/devices/<ieee>/set` | any device command, e.g. `{state:"ON", brightness: 200}` | same as MQTT `set` |
| `api/devices/<ieee>/rename` | `{friendly_name}` | |
| `api/devices/<ieee>/remove` | `{}` | control-only |
| `api/devices/<ieee>/interview` | `{}` | |
| `api/devices/<ieee>/identify` | `{}` | identify 10 s |
| `api/map/refresh` | `{}` | walks neighbour tables of coordinator + routers (takes seconds) |
| `api/rotate_network_key` | `{confirm: "I understand all devices must be re-paired"}` | control-only |
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
* `mqtt.tls.client_ca` is valid in **every** TLS mode (auto or custom): when set, clients must present a certificate signed by it (mTLS) — the Mosquitto "Require client certificate" equivalent.

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
| `POST api/import/preview` | `{ "configuration.yaml"?: text, "database.db"?: text, "coordinator_backup.json"?: text }` (control-only) → `{ok, network:{found, source, channel, pan_id, ext_pan_id, frame_counter, key_is_z2m_default, coordinator_ieee}, devices:[{ieee, friendly_name, model, manufacturer, router, endpoints, interviewed}], warnings:[..]}` |
| `POST api/import/apply` | same body → `{ok, devices, network_adopted, summary, restart_required}` — devices appear immediately; a restart is needed when the network was adopted |

Dashboard data: use `GET api/devices` (list shape includes `state`, `endpoints[].category`, `lqi`, `available`) and per-device `exposes` from `GET api/devices/<ieee>` (cache per device; features don't change unless re-interviewed).
