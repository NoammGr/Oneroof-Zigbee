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
        │
 oneroof_zigbee.mqtt       our own MQTT 3.1.1 broker (+ in-process client)
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
`{"temperature": 21.3}`.

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
