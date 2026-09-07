# OneRoof Zigbee — architecture & conventions

A from-scratch, security-first Zigbee ⇄ MQTT gateway with its own MQTT broker.
Every layer is written from scratch; no code is taken from other projects.

## Layers

```
 CC2652 dongle (TI Z-Stack firmware — the only vendor component; it IS the radio)
        │  serial, UNPI framing
 oneroof_zigbee.znp        UNPI codec, ZNP request/response, coordinator bring-up
        │  AF_INCOMING_MSG / AF_DATA_REQUEST  (raw APS payloads)
 oneroof_zigbee.zcl        ZCL frame codec, attribute types, cluster models
        │  typed attribute reports / commands
 oneroof_zigbee.gateway    device registry, interview, state, security policy
        │  features (what a device exposes), corrected by
 oneroof_zigbee.quirks     model knowledge: kind/vendor, feature overrides, vendor report codecs
        │  ├─ quirks_tuya   Tuya datapoint conventions: infer a family from what a device reported
        │  └─ definitions   user definitions (definitions.yaml) compiled to Quirks, precedence over the table
        │
 oneroof_zigbee.mqtt       our own MQTT broker, 3.1.1 and 5 clients (+ in-process client)
        │
 oneroof_zigbee.ha         Home Assistant MQTT discovery payloads
```

## Conventions (all modules)

* Python ≥ 3.11, `asyncio`, full type hints, `from __future__ import annotations`.
* Allowed third-party deps: `pyserial-asyncio`, `cryptography`, `pyyaml`. Nothing else.
* Every wire codec is a pure function / dataclass, unit-tested without hardware.
* No `print`; use `logging.getLogger("oneroof_zigbee.<module>")`.
* Secrets never logged. Keys are `bytes`, rendered only as `<redacted>`.
* Byte order on the Zigbee wire is **little-endian** everywhere (ZNP and ZCL).
* IEEE addresses are represented as `int` internally and `"0x00124b00deadbeef"` (16 hex) in MQTT/JSON.

## Interfaces between modules

### znp → gateway
```python
@dataclass
class IncomingAps:
    src_addr: int      # NWK short address
    src_ep: int
    dst_ep: int
    cluster: int
    group: int
    lqi: int
    secure: bool       # APS-level security flag from firmware
    seq: int
    payload: bytes     # raw ZCL frame
```
`Coordinator.on_aps(cb)`, `Coordinator.on_device_joined(cb)`, `Coordinator.on_device_left(cb)`,
`Coordinator.send_aps(dst, dst_ep, src_ep, cluster, payload)`, `Coordinator.permit_join(seconds)`,
`Coordinator.add_install_code(ieee, install_code_bytes)`.

### zcl
```python
@dataclass
class ZclFrame:
    frame_type: int      # 0 = global, 1 = cluster-specific
    manufacturer: int | None
    direction: int       # 0 client→server, 1 server→client
    disable_default_response: bool
    seq: int
    command: int
    payload: bytes

def decode_frame(data: bytes) -> ZclFrame
def encode_frame(frame: ZclFrame) -> bytes
```
Global commands: ReadAttributes(0x00)/Rsp(0x01), WriteAttributes(0x02)/Rsp(0x04),
ConfigureReporting(0x06)/Rsp(0x07), ReportAttributes(0x0A), DefaultResponse(0x0B).

`zcl.clusters` exposes `Cluster` models with `id`, `name`, `attributes: dict[int, Attribute]`
and decoders that turn attribute values into plain JSON-able state, e.g.
`{"temperature": 21.3}`. `zcl.vendor` holds the pure codecs for vendor-private payloads
(Aqara tag/type/value reports, Tuya datapoints).

### quirks (model knowledge)

`features.generic_features` derives controls from clusters alone; that is right for
well-behaved Zigbee 3.0 products and wrong for the rest (a door sensor reporting contact
through the On/Off cluster would become a switch). `quirks.QUIRKS` is a declarative table
keyed by (manufacturer pattern, model pattern) → `Quirk`: the human `kind` and `vendor`, a
coarse `category`, features to drop/add/re-label, how the On/Off attribute is to be read
(`on_off_as`), the names of multi-gang endpoints, which clusters may be bound (`()` for
sleepy devices that reject binds), and how the vendor's private reports map to state
(Aqara tags, Tuya datapoint maps, multistate buttons, analog inputs, remote commands).
`quirks.describe(dev)` is what `Device.kind/vendor/category` return; unknown models go
through `classify_device` (IAS zone type, measurement clusters, metering, device ids,
battery-powered on/off-only → remote). The gateway runs `decode_vendor_attributes`
before the standard decoders and `translate_state` after them, so published keys
(`contact`, `state_l1`, `action`…) are the device's keys regardless of how the value
arrived; `ha.discovery` builds entities from the same feature list. Rule for entries:
precision beats breadth — a quirk claims only what the model does; the rest stays generic.

Two layers sit on top of the table for models it does not know:

* `quirks_tuya` — the gateway records every Tuya datapoint a device reports as
  `context["tuya_seen"] = {dp: {type, last, ts}}`. For a datapoint device without a map,
  `infer()` matches the seen `(dp, wire type)` pairs against family *signatures*
  (thermostat, cover, temperature/humidity, smoke, presence radar, switch, soil, light,
  siren, and the single-bool sensors). A family is chosen only when exactly one fits
  after pruning families that explain strictly less; within it a datapoint becomes a
  feature only when its observed wire type agrees with the convention. The result is a
  `Dp` tuple with `inferred=True` (surfaced as `"inferred": true` in the feature dict);
  everything else stays `dp_<n>`. `quirks.tuya_dps(dev)` is the single entry point the
  decoder, the encoder and `shape_features` use, so state keys, commands and entities
  always agree.
* `definitions` — `<data_dir>/definitions.yaml` (0600) holds user definitions keyed by a
  (manufacturer pattern, model pattern): kind/vendor/category/on_off_as overrides, keys to
  remove and a datapoint list. `compile_quirk` merges one over the built-in entry for the
  same model (same-id datapoints replace, new ones add) and the gateway installs the store
  with `quirks.set_definitions`, so `find_quirk` consults it first. Saving, deleting or
  importing a definition snapshots every device's layout (discovery topics + feature keys),
  then `Gateway.apply_layout_changes` rebuilds datapoint state from `tuya_seen`, drops stale
  keys, blanks retained configs of entities that disappeared and re-announces — no restart,
  legacy identities respected. The UI exposes this as the Datapoints tab, the Type &
  category card and Settings → Device definitions (`/api/definitions…`).

### mqtt
```python
class Broker:
    def __init__(self, *, auth: Authenticator, acl: Acl, host, port, tls: ssl.SSLContext | None)
    async def start(self); async def stop(self)
    # in-process fast path for the gateway, no TCP roundtrip:
    async def publish(self, topic: str, payload: bytes, retain: bool = False, qos: int = 0)
    def subscribe(self, topic_filter: str, cb: Callable[[str, bytes], Awaitable[None]])
```
Broker security rules:
* Anonymous connections are **rejected** (CONNACK 0x05). No opt-out.
* Passwords stored as scrypt hashes, verified with `hmac.compare_digest`.
* ACL per user: list of allowed publish filters and subscribe filters. Default deny.
* `$SYS/#` and the gateway's control topics are writable only by the gateway's own user.
* Max packet size 256 KiB; slow/idle clients dropped at 1.5× keepalive.
* QoS 2 is downgraded to QoS 1 (documented).

## MQTT topic layout (base topic `oneroof/zigbee` by default)

```
oneroof/zigbee/bridge/state                      online|offline   (retained, LWT)
oneroof/zigbee/bridge/event                      {"type": "device_joined"|"device_left"|"permit_join"|"security_alert", ...}
oneroof/zigbee/bridge/devices                    retained JSON list
oneroof/zigbee/bridge/request/permit_join        {"seconds": 60, "install_code": "...optional..."}  ← ACL-restricted
oneroof/zigbee/bridge/request/remove             {"ieee": "0x..."}
oneroof/zigbee/bridge/request/rotate_network_key {}                                                 ← ACL-restricted
oneroof/zigbee/<ieee>/state                      retained JSON state
oneroof/zigbee/<ieee>/set                        JSON command
oneroof/zigbee/<ieee>/availability               online|offline
homeassistant/<component>/<ieee>_<object>/config   HA discovery (retained)
```

## What the gateway says a device *is* (gateway.py)

A published state is a claim about the world, and every consumer (Home Assistant, the Apple Home
bridge, the Statistics app) repeats it. The rules that keep it honest:

* **Reports are the primary source.** At interview the gateway binds each state cluster to itself
  and configures reporting. A bind the device refuses (ZDO status) is recorded as
  `bind failed (0x..)`, never as `ok`; a setup that timed out is recorded as `failed: …`. Both are
  retried the next time the device talks (that is the only moment a battery device listens), at
  most every `REPORTING_RETRY_S`. A ZCL refusal (`status 0x8c`, unreportable attribute) is the
  device's final word and is not retried.
* **Devices that cannot or do not report are asked.** `_poll_silent_routers` runs each monitor
  tick and goes by *state evidence* — the last on/off, level, cover, thermostat, colour or Tuya
  datapoint read or report — not by any frame: a plug reporting power every ten seconds says
  nothing about its button. Mains devices past `ROUTER_POLL_AFTER_S` (or
  `UNREPORTED_POLL_AFTER_S` when their reporting is not `ok`) get a full `_refresh_state`: every
  endpoint, every state cluster, through `quirks.translate_state` so a second gang lands on
  `state_l2`. Two unanswered polls in a row and *nothing heard since the first miss* mark the
  device offline (`availability` = offline, audit `device_unanswering`); it is then tried after
  5, 10, 15, 30 minutes (`POLL_BACKOFF_S`) and comes back the moment it is heard, with a refresh
  scheduled — it came back in whatever state its firmware chose. A device that fails the polls
  but *has* been heard since the first miss (a plug whose reports arrive while our unicasts to
  it die on a broken route) is alive: it stays online with what it last reported, is written up
  once (`device_not_answering_reads`, log line "reports but does not answer reads"), and is asked
  on the same growing backoff. Its reports do not clear that backoff — only an answered read or
  an offline→online transition does; clearing it on every frame is what made such a device flap
  offline/online every minute or two all night in 2.13.0.
* **Nothing remembered is trusted after a gap.** After our own start, after the serial link comes
  back (`coordinator_back`), and after a device rejoins (a power cut), every device that can answer
  is asked (`_refresh_all_states` / `_schedule_refresh`). While the radio is gone `bridge/state` is
  `offline` — on the built-in broker by the gateway, on an external broker by that broker's last
  will — so consumers mark everything unavailable rather than show the last word.
* **Commands are optimistic only where the outcome is certain.** `{"state": "OFF", "brightness": N}`
  is an off order (the level command would switch the light back on). `TOGGLE` and any command
  that raised are followed by a read; only the device knows what they left behind.
* **The registry file follows the truth.** State and availability changes set `_dirty`; the
  monitor tick and `stop()` write the file, so a restart publishes the last known state and not one
  from the last incidental save.
