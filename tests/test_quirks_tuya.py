"""Tuya datapoint heuristics: features inferred for TS0601 models without a map.

Every case feeds synthetic report sequences (synthetic IEEEs, invented manufacturer ids that are
not in the built-in table) and checks what is inferred — and, just as important, what is not.
"""

from __future__ import annotations

import struct

from oneroof_zigbee import quirks, quirks_tuya as qt
from oneroof_zigbee.devices import Device, Endpoint
from oneroof_zigbee.features import features_for
from oneroof_zigbee.ha.discovery import discovery_messages
from oneroof_zigbee.zcl import vendor as vz

IEEE = 0x00158D0000000011
B, V, E, S = vz.TUYA_BOOL, vz.TUYA_VALUE, vz.TUYA_ENUM, vz.TUYA_STRING


def mk(manufacturer: str = "_TZE200_zzunknown", model: str = "TS0601", *, power: str = "battery") -> Device:
    d = Device(ieee=IEEE, nwk=0x1234, friendly_name="t", manufacturer=manufacturer, model=model, power_source=power, is_router=power == "mains")
    d.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0x0000, 0x0004, 0x0005, 0xEF00], [0x0019, 0x000A])
    return d


def _dp(dp: int, dtype: int, data: bytes) -> bytes:
    return bytes([dp, dtype]) + len(data).to_bytes(2, "big") + data


def _val(n: int) -> bytes:
    return struct.pack(">i", n)


def report(dev: Device, *dps: tuple[int, int, bytes], seq: int = 1) -> dict:
    """Feed one dataReport the way the gateway does: remember the datapoints, then decode."""
    payload = seq.to_bytes(2, "big") + b"".join(_dp(d, t, v) for d, t, v in dps)
    decoded = vz.decode_tuya_datapoints(payload)
    qt.record_datapoints(dev, decoded, 1000.0)
    changed = quirks.decode_tuya_values(dev, decoded)
    dev.state.update(changed)
    return changed


def keys(dev: Device) -> dict[str, dict]:
    return {f["key"]: f for f in features_for(dev)}


def ha(dev: Device) -> dict[str, tuple[str, dict]]:
    import json
    out = {}
    for topic, payload in discovery_messages(dev, "oz", "homeassistant"):
        parts = topic.split("/")
        out[parts[-2]] = (parts[1], json.loads(payload))
    return out


def test_nothing_seen_nothing_inferred():
    dev = mk()
    assert qt.infer(dev) == (None, ())
    assert dev.kind == "Tuya device (datapoints)" and dev.category == "unknown"
    assert "dp_1" not in keys(dev)


def test_smoke_detector():
    dev = mk("_TZE200_smokezzz")
    st = report(dev, (1, E, b"\x01"), (14, E, b"\x02"), (15, V, _val(87)))
    fam, dps = qt.infer(dev)
    assert fam.name == "smoke" and [d.dp for d in dps] == [1, 14, 15]
    assert st == {"smoke": False, "battery_low": False, "battery": 87}
    assert report(dev, (1, E, b"\x00")) == {"smoke": True}
    assert dev.kind == "Smoke detector" and dev.category == "sensor"
    k = keys(dev)
    assert k["smoke"]["inferred"] is True and k["smoke"]["type"] == "binary" and k["battery"]["inferred"] is True
    h = ha(dev)
    assert h["smoke"][0] == "binary_sensor" and h["smoke"][1]["device_class"] == "smoke"
    assert h["battery"][1]["device_class"] == "battery"


def test_temperature_humidity_sensor_with_scale_guess():
    dev = mk("_TZE200_thzzzzzz")
    st = report(dev, (1, V, _val(235)), (2, V, _val(47)), (4, V, _val(90)))
    assert st == {"temperature": 23.5, "humidity": 47, "battery": 90}
    assert dev.kind == "Temperature/humidity sensor"
    assert ha(dev)["temperature"][1]["device_class"] == "temperature"
    # a humidity reported ×10 is recognised from its magnitude
    dev10 = mk("_TZE200_thzzzzz2")
    assert report(dev10, (1, V, _val(201)), (2, V, _val(478))) == {"temperature": 20.1, "humidity": 47.8}
    # an unknown datapoint on a known family stays raw and is still exposed
    assert report(dev10, (19, V, _val(5))) == {"dp_19": 5}
    k = keys(dev10)
    assert k["dp_19"]["type"] == "numeric" and "inferred" not in k["dp_19"]
    # a datapoint whose wire type contradicts the convention is not mapped either
    assert report(dev10, (4, E, b"\x01")) == {"dp_4": 1}


def test_trv_is_a_climate_entity_and_writable():
    dev = mk("_TZE200_trvzzzzz")
    st = report(dev, (2, V, _val(215)), (3, V, _val(201)), (4, E, b"\x01"), (7, B, b"\x01"))
    assert st == {"current_heating_setpoint": 21.5, "local_temperature": 20.1, "preset": "manual", "child_lock": "LOCK"}
    assert dev.kind == "Thermostat/TRV" and dev.category == "climate"
    assert quirks.encode_tuya_command(dev, "current_heating_setpoint", 19, 5) == (5).to_bytes(2, "big") + _dp(2, V, _val(190))
    assert quirks.encode_tuya_command(dev, "child_lock", "UNLOCK", 6) == (6).to_bytes(2, "big") + _dp(7, B, b"\x00")
    assert quirks.encode_tuya_command(dev, "local_temperature", 1, 7) is None
    cl = ha(dev)["climate"][1]
    assert cl["temperature_state_template"] == "{{ value_json.current_heating_setpoint }}" and cl["preset_modes"] == ["schedule", "manual", "boost", "complex", "comfort", "eco"]
    # wall-thermostat layout (16 setpoint, 24 temperature ×10) is the other signature
    wall = mk("_TZE204_wallzzzz", power="mains")
    assert report(wall, (1, B, b"\x01"), (16, V, _val(22)), (24, V, _val(213))) == {"system_mode": "heat", "current_heating_setpoint": 22, "local_temperature": 21.3}
    assert wall.kind == "Thermostat/TRV"


def test_curtain_motor():
    dev = mk("_TZE200_curtainz", power="mains")
    st = report(dev, (1, E, b"\x01"), (3, V, _val(65)), (7, E, b"\x00"))
    assert st == {"cover": "STOP", "position": 65, "work_state": "opening"}
    assert dev.kind == "Curtain motor" and dev.category == "cover"
    assert quirks.encode_tuya_command(dev, "cover", "CLOSE", 1) == (1).to_bytes(2, "big") + _dp(1, E, b"\x02")
    # dp 2 (set position) appears later: position becomes writable and the entity gets a set_position topic
    assert quirks.encode_tuya_command(dev, "position", 30, 2) is None
    report(dev, (2, V, _val(30)))
    assert quirks.encode_tuya_command(dev, "position", 30, 2) == (2).to_bytes(2, "big") + _dp(2, V, _val(30))
    c = ha(dev)["cover"][1]
    assert c["payload_close"] == '{"state": "CLOSE"}' and "set_position_topic" in c


def test_presence_radar_beats_the_single_bool_families():
    dev = mk("_TZE204_radarzzz", power="mains")
    assert report(dev, (1, B, b"\x01")) == {"dp_1": True}           # a lone bool is ambiguous: leak / contact / gas / …
    assert dev.kind == "Tuya device (datapoints)"
    st = report(dev, (9, V, _val(150)), (104, V, _val(120)), (101, V, _val(5)))
    assert st == {"target_distance": 1.5, "illuminance_lux": 120, "detection_delay": 0.5}
    assert dev.kind == "Presence sensor (radar)"
    k = keys(dev)
    assert "presence" in k and "dp_1" not in k and k["detection_delay"]["access"] == "rw" and k["detection_delay"]["category"] == "config"
    assert ha(dev)["presence"][1]["device_class"] == "occupancy"


def test_two_gang_switch():
    dev = mk("_TZE200_switchzz", power="mains")
    st = report(dev, (1, B, b"\x01"), (2, B, b"\x00"), (7, V, _val(0)))
    assert st == {"state_l1": "ON", "state_l2": "OFF", "countdown_l1": 0}
    assert dev.kind == "Wall switch (2 gang)" and dev.category == "switch"
    assert quirks.encode_tuya_command(dev, "state_l2", "ON", 3) == (3).to_bytes(2, "big") + _dp(2, B, b"\x01")
    h = ha(dev)
    assert h["state_l1"][0] == "switch" and h["state_l1"][1]["payload_on"] == '{"state_l1": "ON"}'
    assert h["countdown_l1"][0] == "number"


def test_ambiguous_device_stays_raw():
    # 1 enum + 2 value (cover?) + 15 value (smoke?) → two families fit, nothing is claimed
    dev = mk("_TZE200_ambiguou")
    st = report(dev, (1, E, b"\x00"), (2, V, _val(50)), (15, V, _val(80)))
    assert st == {"dp_1": 0, "dp_2": 50, "dp_15": 80}
    assert qt.infer(dev) == (None, ())
    assert dev.kind == "Tuya device (datapoints)" and dev.category == "unknown"
    k = keys(dev)
    assert {"dp_1", "dp_2", "dp_15"} <= set(k) and all("inferred" not in k[x] for x in ("dp_1", "dp_2", "dp_15"))
    assert ha(dev)["dp_2"][0] == "sensor"
    # 2 value + 3 value (thermostat) plus 5 value (soil): also ambiguous
    dev2 = mk("_TZE200_ambiguo2")
    report(dev2, (2, V, _val(1)), (3, V, _val(2)), (5, V, _val(3)))
    assert qt.infer(dev2) == (None, ())


def test_builtin_map_and_non_tuya_devices_are_left_alone():
    known = mk("_TZE200_ckud7u2l")
    qt.record_datapoints(known, [(1, B, True), (2, B, False)], 1.0)  # looks like a 2-gang switch, but the table knows better
    assert known.kind == "Thermostat/TRV" and [d.dp for d in quirks.tuya_dps(known)][:2] == [2, 3]
    other = Device(ieee=IEEE, nwk=1, friendly_name="x", manufacturer="Acme", model="Thing")
    other.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0x0000, 0x0006], [])
    qt.record_datapoints(other, [(1, B, True), (2, B, False)], 1.0)
    assert not qt.is_tuya_dp_device(other) and quirks.tuya_dps(other) == ()


def test_seen_datapoints_survive_a_registry_round_trip():
    dev = mk("_TZE200_roundtri")
    report(dev, (1, V, _val(235)), (2, V, _val(47)))
    again = Device.from_json(dev.to_json())
    assert qt.seen_datapoints(again) == {1: {"type": V, "last": 235, "ts": 1000.0}, 2: {"type": V, "last": 47, "ts": 1000.0}}
    assert again.kind == "Temperature/humidity sensor"
