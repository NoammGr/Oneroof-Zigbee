"""Unit tests for oneroof_zigbee.zcl (pure codec, no hardware)."""

from __future__ import annotations

import math

import pytest

from oneroof_zigbee.zcl import (
    DataType,
    ZclFrame,
    build_cluster_command,
    build_configure_reporting,
    build_default_response,
    build_read_attributes,
    decode_attributes,
    decode_cluster_command,
    decode_frame,
    decode_global_command,
    decode_value,
    describe_endpoint,
    encode_command,
    encode_frame,
    encode_value,
)
from oneroof_zigbee.zcl.global_commands import (
    ConfigureReporting,
    DefaultResponse,
    DiscoverAttributesResponse,
    ReadAttributes,
    ReadAttributesResponse,
    ReportAttributes,
    ReportingConfigRecord,
    WriteAttributeRecord,
    WriteAttributes,
    WriteAttributesResponse,
)
from oneroof_zigbee.zcl.types import ZclDecodeError

# ---------------------------------------------------------------------------
# Frame
# ---------------------------------------------------------------------------


def test_frame_roundtrip_without_manufacturer() -> None:
    f = ZclFrame(frame_type=1, manufacturer=None, direction=1, disable_default_response=True, seq=0x42, command=0x0A, payload=b"\x01\x02")
    raw = encode_frame(f)
    # fc: type=1 | dir(bit3) | ddr(bit4) = 0x19
    assert raw == bytes([0x19, 0x42, 0x0A, 0x01, 0x02])
    assert decode_frame(raw) == f


def test_frame_roundtrip_with_manufacturer() -> None:
    f = ZclFrame(frame_type=0, manufacturer=0x1234, direction=0, disable_default_response=False, seq=7, command=0x00, payload=b"\x00\x00")
    raw = encode_frame(f)
    assert raw == bytes([0x04, 0x34, 0x12, 0x07, 0x00, 0x00, 0x00])
    assert decode_frame(raw) == f


def test_frame_too_short() -> None:
    with pytest.raises(ValueError):
        decode_frame(b"\x04\x34")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dtype,value,raw",
    [
        (DataType.bool_, True, b"\x01"),
        (DataType.bool_, False, b"\x00"),
        (DataType.uint8, 200, b"\xc8"),
        (DataType.uint16, 0x1234, b"\x34\x12"),
        (DataType.uint24, 0x123456, b"\x56\x34\x12"),
        (DataType.uint32, 0xDEADBEEF, b"\xef\xbe\xad\xde"),
        (DataType.uint48, 0x0000_1234_5678_9ABC, b"\xbc\x9a\x78\x56\x34\x12"),
        (DataType.uint64, 2**64 - 2, b"\xfe" + b"\xff" * 7),
        (DataType.int8, -5, b"\xfb"),
        (DataType.int16, -1000, (-1000).to_bytes(2, "little", signed=True)),
        (DataType.int24, -70000, (-70000).to_bytes(3, "little", signed=True)),
        (DataType.int32, -2, b"\xfe\xff\xff\xff"),
        (DataType.enum8, 3, b"\x03"),
        (DataType.enum16, 0x0015, b"\x15\x00"),
        (DataType.bitmap8, 0x81, b"\x81"),
        (DataType.bitmap16, 0x8001, b"\x01\x80"),
        (DataType.data8, 0xFF, b"\xff"),
        (DataType.single, 1.5, b"\x00\x00\xc0\x3f"),
        (DataType.double, -2.25, b"\x00\x00\x00\x00\x00\x00\x02\xc0"),
        (DataType.string, "abc", b"\x03abc"),
        (DataType.octstr, b"\x00\x01", b"\x02\x00\x01"),
        (DataType.long_string, "hi", b"\x02\x00hi"),
        (DataType.long_octstr, b"\xaa", b"\x01\x00\xaa"),
        (DataType.eui64, 0x00124B00DEADBEEF, b"\xef\xbe\xad\xde\x00\x4b\x12\x00"),
        (DataType.key128, bytes(range(16)), bytes(range(16))),
        (DataType.utc, 0x01020304, b"\x04\x03\x02\x01"),
        (DataType.cluster_id, 0x0402, b"\x02\x04"),
        (DataType.attr_id, 0x0001, b"\x01\x00"),
        (DataType.nodata, None, b""),
    ],
)
def test_type_roundtrip(dtype: DataType, value: object, raw: bytes) -> None:
    assert encode_value(dtype, value) == raw
    decoded, off = decode_value(dtype, b"\xaa" + raw, 1)
    assert decoded == value
    assert off == 1 + len(raw)


def test_semi_roundtrip() -> None:
    raw = encode_value(DataType.semi, 0.5)
    assert len(raw) == 2
    assert decode_value(DataType.semi, raw)[0] == 0.5


@pytest.mark.parametrize(
    "dtype,raw",
    [
        (DataType.uint8, b"\xff"),
        (DataType.uint16, b"\xff\xff"),
        (DataType.uint48, b"\xff" * 6),
        (DataType.int8, b"\x80"),
        (DataType.int16, b"\x00\x80"),
        (DataType.int32, b"\x00\x00\x00\x80"),
        (DataType.enum8, b"\xff"),
        (DataType.enum16, b"\xff\xff"),
        (DataType.bool_, b"\xff"),
        (DataType.single, b"\x00\x00\xc0\x7f"),
        (DataType.double, b"\x00\x00\x00\x00\x00\x00\xf8\x7f"),
        (DataType.string, b"\xff"),
        (DataType.octstr, b"\xff"),
        (DataType.long_string, b"\xff\xff"),
        (DataType.eui64, b"\xff" * 8),
        (DataType.utc, b"\xff" * 4),
    ],
)
def test_invalid_sentinels_decode_to_none(dtype: DataType, raw: bytes) -> None:
    value, off = decode_value(dtype, raw)
    assert value is None
    assert off == len(raw)
    # and None encodes back to the sentinel
    enc = encode_value(dtype, None)
    if dtype in (DataType.single, DataType.double):
        assert math.isnan(decode_value(dtype, enc)[0] or math.nan)
    else:
        assert enc == raw


def test_bitmap_ff_is_not_invalid() -> None:
    assert decode_value(DataType.bitmap8, b"\xff")[0] == 0xFF
    assert decode_value(DataType.data16, b"\xff\xff")[0] == 0xFFFF


def test_array_and_struct_decode() -> None:
    # array of 2 × uint16
    arr = bytes([DataType.uint16, 0x02, 0x00]) + b"\x01\x00\x02\x00"
    assert decode_value(DataType.array, arr) == ([1, 2], len(arr))
    # struct: uint8 7, string "x"
    st = b"\x02\x00" + bytes([DataType.uint8, 7]) + bytes([DataType.string, 1]) + b"x"
    assert decode_value(DataType.struct_, st) == ([7, "x"], len(st))
    # roundtrip encode
    assert encode_value(DataType.array, (DataType.uint16, [1, 2])) == arr
    assert encode_value(DataType.struct_, [(DataType.uint8, 7), (DataType.string, "x")]) == st


def test_truncated_value_raises() -> None:
    with pytest.raises(ZclDecodeError):
        decode_value(DataType.uint16, b"\x01")
    with pytest.raises(ZclDecodeError):
        decode_value(DataType.string, b"\x05ab")


# ---------------------------------------------------------------------------
# Global commands
# ---------------------------------------------------------------------------


def test_read_attributes_response_temperature() -> None:
    # Read Attributes Response, attr 0x0000 status SUCCESS type int16 value 2135
    payload = b"\x00\x00" + b"\x00" + bytes([DataType.int16]) + (2135).to_bytes(2, "little")
    frame = decode_frame(bytes([0x18, 0x05, 0x01]) + payload)
    assert frame.is_global and frame.command == 0x01 and frame.direction == 1
    rsp = decode_global_command(frame)
    assert isinstance(rsp, ReadAttributesResponse)
    assert rsp.records[0].attr == 0 and rsp.records[0].value == 2135
    assert decode_attributes(0x0402, rsp.successful()) == {"temperature": 21.35}
    assert rsp.encode() == payload


def test_read_attributes_response_with_failure_record() -> None:
    payload = b"\x04\x00\x86" + b"\x05\x00\x00" + bytes([DataType.string, 3]) + b"abc"
    rsp = ReadAttributesResponse.decode(payload)
    assert rsp.records[0].status == 0x86 and rsp.records[0].value is None
    assert rsp.records[1].value == "abc"
    assert decode_attributes(0x0000, rsp.successful()) == {"model_id": "abc"}


def test_report_attributes_decode() -> None:
    # humidity 0x0405 attr 0 uint16 5523 + unknown attr 0x0010 uint8 3
    payload = b"\x00\x00" + bytes([DataType.uint16]) + (5523).to_bytes(2, "little") + b"\x10\x00" + bytes([DataType.uint8, 3])
    rep = ReportAttributes.decode(payload)
    assert [(r.attr, r.value) for r in rep.records] == [(0, 5523), (0x10, 3)]
    assert decode_attributes(0x0405, rep.pairs()) == {"humidity": 55.23, "relative_humidity_0x0010": 3}
    assert rep.encode() == payload


def test_read_attributes_build() -> None:
    raw = build_read_attributes(3, [0x0004, 0x0005])
    assert raw == bytes([0x10, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00])
    raw = build_read_attributes(3, [0x0004], manufacturer=0x115F)
    assert raw == bytes([0x14, 0x5F, 0x11, 0x03, 0x00, 0x04, 0x00])
    assert ReadAttributes.decode(decode_frame(raw).payload).attrs == [4]


def test_configure_reporting_encode() -> None:
    recs = [
        ReportingConfigRecord(attr=0x0000, dtype=DataType.int16, min_interval=10, max_interval=3600, reportable_change=50),
        ReportingConfigRecord(attr=0x0000, dtype=DataType.bool_, min_interval=0, max_interval=300),
    ]
    raw = build_configure_reporting(9, recs)
    expected = (
        bytes([0x10, 0x09, 0x06])
        + b"\x00" + b"\x00\x00" + bytes([DataType.int16]) + b"\x0a\x00" + b"\x10\x0e" + b"\x32\x00"
        + b"\x00" + b"\x00\x00" + bytes([DataType.bool_]) + b"\x00\x00" + b"\x2c\x01"
    )
    assert raw == expected
    back = ConfigureReporting.decode(decode_frame(raw).payload)
    assert back.records[0].reportable_change == 50 and back.records[1].reportable_change is None
    assert back.records[1].max_interval == 300


def test_configure_reporting_response_short_form() -> None:
    rsp = decode_global_command(decode_frame(bytes([0x18, 0x01, 0x07, 0x00])))
    assert rsp.all_ok
    rsp = decode_global_command(decode_frame(bytes([0x18, 0x01, 0x07, 0x8C, 0x00, 0x02, 0x00])))
    assert not rsp.all_ok and rsp.records[0].attr == 2


def test_write_attributes_roundtrip() -> None:
    wa = WriteAttributes([WriteAttributeRecord(0x0010, DataType.eui64, 0x00124B00DEADBEEF)])
    raw = wa.encode()
    assert raw == b"\x10\x00\xf0" + b"\xef\xbe\xad\xde\x00\x4b\x12\x00"
    assert WriteAttributes.decode(raw) == wa
    assert WriteAttributesResponse.decode(b"\x00").all_ok
    r = WriteAttributesResponse.decode(b"\x88\x10\x00")
    assert not r.all_ok and r.records[0].attr == 0x10


def test_default_response() -> None:
    raw = build_default_response(0x21, cmd=0x0A, status=0x00, direction=0)
    assert raw == bytes([0x10, 0x21, 0x0B, 0x0A, 0x00])
    dr = decode_global_command(decode_frame(raw))
    assert dr == DefaultResponse(0x0A, 0x00)


def test_discover_attributes_response() -> None:
    rsp = DiscoverAttributesResponse.decode(b"\x01" + b"\x00\x00\x29" + b"\x01\x00\x29")
    assert rsp.complete and [(a.attr, a.dtype) for a in rsp.attributes] == [(0, 0x29), (1, 0x29)]
    assert rsp.encode() == b"\x01\x00\x00\x29\x01\x00\x29"


# ---------------------------------------------------------------------------
# Cluster converters
# ---------------------------------------------------------------------------


def test_on_off_decode_and_commands() -> None:
    assert decode_attributes(0x0006, [(0, True)]) == {"state": "ON"}
    assert decode_attributes(0x0006, [(0, False)]) == {"state": "OFF"}
    assert encode_command(0x0006, "on", {}) == (0x01, b"")
    assert encode_command(0x0006, "off") == (0x00, b"")
    assert encode_command(0x0006, "toggle") == (0x02, b"")
    cmd, payload = encode_command(0x0006, "on")
    assert build_cluster_command(5, cmd, payload) == bytes([0x11, 0x05, 0x01])


def test_level_command_bytes() -> None:
    cmd, payload = encode_command(0x0008, "move_to_level_with_on_off", {"level": 128, "transition_time": 10})
    assert (cmd, payload) == (0x04, b"\x80\x0a\x00")
    assert build_cluster_command(1, cmd, payload, disable_default_response=False) == bytes([0x01, 0x01, 0x04, 0x80, 0x0A, 0x00])
    cmd, payload = encode_command(0x0008, "move_to_level", {"level": 254})
    assert (cmd, payload) == (0x00, b"\xfe\x00\x00")
    assert decode_attributes(0x0008, [(0, 200)]) == {"brightness": 200}
    with pytest.raises(ValueError):
        encode_command(0x0008, "move_to_level", {})


def test_color_commands_and_decode() -> None:
    cmd, payload = encode_command(0x0300, "move_to_color", {"x": 0.5, "y": 0.25, "transition_time": 5})
    assert cmd == 0x07
    assert payload == (32768).to_bytes(2, "little") + (16384).to_bytes(2, "little") + b"\x05\x00"
    cmd, payload = encode_command(0x0300, "move_to_color_temp", {"color_temp": 370})
    assert (cmd, payload) == (0x0A, b"\x72\x01\x00\x00")
    cmd, payload = encode_command(0x0300, "move_to_hue_and_saturation", {"hue": 10, "saturation": 200, "transition_time": 1})
    assert (cmd, payload) == (0x06, b"\x0a\xc8\x01\x00")
    st = decode_attributes(0x0300, [(3, 32768), (4, 16384), (7, 250), (8, 2)])
    assert st["color"] == {"x": 0.5, "y": 0.25}
    assert st["color_temp"] == 250 and st["color_mode"] == "color_temp"


def test_identify_command() -> None:
    assert encode_command(0x0003, "identify", {"time": 30}) == (0x00, b"\x1e\x00")


def test_sensor_decoders() -> None:
    assert decode_attributes(0x0403, [(0, 1013)]) == {"pressure": 1013}
    assert decode_attributes(0x0406, [(0, 0x01)]) == {"occupancy": True}
    assert decode_attributes(0x0406, [(0, 0x00)]) == {"occupancy": False}
    assert decode_attributes(0x0402, [(0, None)]) == {}
    assert decode_attributes(0x0402, [(0, -550)]) == {"temperature": -5.5}
    assert decode_attributes(0x0001, [(0x20, 30), (0x21, 150)]) == {"voltage": 3.0, "battery": 75.0}


def test_illuminance_conversion() -> None:
    st = decode_attributes(0x0400, [(0, 1)])
    assert st == {"illuminance": 1, "illuminance_lux": 1.0}
    st = decode_attributes(0x0400, [(0, 20001)])
    assert st["illuminance_lux"] == pytest.approx(100.0, abs=0.01)
    assert decode_attributes(0x0400, [(0, 0)])["illuminance_lux"] == 0.0


def test_metering_uint48_decode() -> None:
    # Report: attr 0 type uint48 value 12345 Wh (default divisor 1000 → 12.345 kWh)
    payload = b"\x00\x00" + bytes([DataType.uint48]) + (12345).to_bytes(6, "little")
    rep = ReportAttributes.decode(payload)
    assert rep.records[0].dtype == DataType.uint48 and rep.records[0].value == 12345
    assert decode_attributes(0x0702, rep.pairs()) == {"energy": 12.345}
    # with explicit multiplier/divisor remembered in context
    ctx: dict = {}
    assert decode_attributes(0x0702, [(0x0301, 1), (0x0302, 100)], ctx) == {}
    assert decode_attributes(0x0702, [(0, 12345)], ctx) == {"energy": 123.45}
    # instantaneous demand int24 negative
    payload = b"\x00\x04" + bytes([DataType.int24]) + (-1500).to_bytes(3, "little", signed=True)
    rep = ReportAttributes.decode(payload)
    # divisor 100 → -15 kW → reported in W
    assert decode_attributes(0x0702, rep.pairs(), ctx)["power"] == -15000.0
    # default divisor 1000 → -1.5 kW → -1500 W
    assert decode_attributes(0x0702, rep.pairs())["power"] == -1500.0


def test_electrical_measurement_divisors() -> None:
    ctx: dict = {}
    st = decode_attributes(0x0B04, [(0x0505, 230), (0x0508, 1500), (0x050B, 345)], ctx)
    assert st == {"voltage": 230, "current": 1.5, "power": 345}
    decode_attributes(0x0B04, [(0x0600, 1), (0x0601, 10), (0x0602, 1), (0x0603, 100), (0x0604, 1), (0x0605, 10)], ctx)
    st = decode_attributes(0x0B04, [(0x0505, 2301), (0x0508, 150), (0x050B, 3450)], ctx)
    assert st == {"voltage": 230.1, "current": 1.5, "power": 345}


def test_window_covering() -> None:
    assert decode_attributes(0x0102, [(8, 30)]) == {"position": 70}
    assert encode_command(0x0102, "go_to_lift_percentage", {"percentage": 25}) == (0x05, b"\x19")
    assert encode_command(0x0102, "up_open") == (0x00, b"")
    assert encode_command(0x0102, "down_close") == (0x01, b"")
    assert encode_command(0x0102, "stop") == (0x02, b"")


def test_thermostat() -> None:
    st = decode_attributes(0x0201, [(0, 2150), (0x12, 2000), (0x1C, 4)])
    assert st == {"local_temperature": 21.5, "current_heating_setpoint": 20.0, "system_mode": "heat"}


def test_basic_cluster() -> None:
    st = decode_attributes(0x0000, [(4, "LUMI"), (5, "lumi.sensor_magnet"), (7, 3), (0x4000, "1.0")])
    assert st["manufacturer_name"] == "LUMI" and st["model_id"] == "lumi.sensor_magnet"
    assert st["power_source"] == "battery" and st["sw_build_id"] == "1.0"


# ---------------------------------------------------------------------------
# IAS Zone
# ---------------------------------------------------------------------------


def test_ias_zone_status_notification_contact() -> None:
    ctx = {"zone_type": 0x0015}  # contact switch
    # zone_status alarm1 set, extended 0, zone id 1, delay 0
    payload = b"\x01\x00" + b"\x00" + b"\x01" + b"\x00\x00"
    frame = decode_frame(bytes([0x19, 0x33, 0x00]) + payload)
    assert frame.is_cluster_specific and frame.direction == 1
    out = decode_cluster_command(0x0500, frame.command, frame.direction, frame.payload, ctx)
    assert out["command"] == "zone_status_change_notification"
    assert out["zone_status"] == 1 and out["zone_id"] == 1
    assert out["contact"] is False and out["tamper"] is False and out["battery_low"] is False
    # closed + battery low
    out = decode_cluster_command(0x0500, 0x00, 1, b"\x08\x00\x00\x01\x00\x00", ctx)
    assert out["contact"] is True and out["battery_low"] is True


def test_ias_zone_types_via_attributes() -> None:
    ctx: dict = {}
    # zone type learned from attribute read (motion sensor) then status attr report
    assert decode_attributes(0x0500, [(1, 0x000D)], ctx)["zone_type"] == "motion"
    assert decode_attributes(0x0500, [(2, 0x0001)], ctx)["occupancy"] is True
    ctx = {"zone_type": 0x002A}
    assert decode_attributes(0x0500, [(2, 0x0005)], ctx) == {"water_leak": True, "tamper": True, "battery_low": False}
    ctx = {"zone_type": 0x0028}
    assert decode_attributes(0x0500, [(2, 0)], ctx)["smoke"] is False
    # unknown type falls back to generic alarms
    out = decode_attributes(0x0500, [(2, 0x0002)], {})
    assert out["alarm_1"] is False and out["alarm_2"] is True


def test_ias_enroll_flow() -> None:
    ctx: dict = {}
    req = decode_cluster_command(0x0500, 0x01, 1, b"\x15\x00\x5f\x11", ctx)
    assert req["command"] == "zone_enroll_request" and req["zone_type"] == 0x0015 and req["manufacturer"] == 0x115F
    assert ctx["zone_type"] == 0x0015 and req["zone_type_name"] == "contact"
    cmd, payload = encode_command(0x0500, "zone_enroll_response", {"enroll_response_code": 0, "zone_id": 0x2A})
    assert (cmd, payload) == (0x00, b"\x00\x2a")
    raw = build_cluster_command(0x33, cmd, payload, direction=0)
    assert raw == bytes([0x11, 0x33, 0x00, 0x00, 0x2A])
    rsp = decode_cluster_command(0x0500, 0x00, 0, payload)
    assert rsp["command"] == "zone_enroll_response" and rsp["enroll_response"] == "success"


def test_unknown_cluster_command_does_not_crash() -> None:
    out = decode_cluster_command(0x1234, 0x05, 0, b"\x01\x02")
    assert out["payload"] == "0102" and out["command"] == "cmd_0x05"
    out = decode_cluster_command(0x0500, 0x00, 1, b"\x01")  # truncated notification
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


def test_describe_endpoint_categories() -> None:
    assert describe_endpoint([0x0000, 0x0006, 0x0008, 0x0300], [], 0x010D)["category"] == "light"
    assert describe_endpoint([0x0000, 0x0006, 0x0008], [], None)["category"] == "light"
    assert describe_endpoint([0x0000, 0x0006, 0x0B04], [], None)["category"] == "plug"
    assert describe_endpoint([0x0000, 0x0006], [], None)["category"] == "switch"
    assert describe_endpoint([0x0000, 0x0402, 0x0405], [], 0x0302)["category"] == "sensor"
    assert describe_endpoint([0x0000, 0x0500], [], None)["category"] == "sensor"
    assert describe_endpoint([0x0000, 0x0102], [], 0x0202)["category"] == "cover"
    assert describe_endpoint([0x0000, 0x0201], [], None)["category"] == "climate"
    assert describe_endpoint([0x0000], [0x0006], None)["category"] == "switch"
    d = describe_endpoint([0x0000, 0x0019], [], 0x0051)
    assert d["category"] == "plug" and d["device_type"] == "smart_plug"
    assert d["in_clusters"][1]["name"] == "ota"
    assert describe_endpoint([0x0000], [], None)["category"] == "unknown"


def test_read_attributes_response_tolerates_bad_tail():
    from oneroof_zigbee.zcl import ReadAttributesResponse, ReportAttributes
    good = bytes.fromhex("0400 00 42 04") + b"ACME"
    bad = bytes.fromhex("0500 00 40 ffffff")  # unknown data type 0x40
    r = ReadAttributesResponse.decode(good + bad)
    assert len(r.records) == 1 and r.records[0].value == "ACME"
    rep = ReportAttributes.decode(bytes.fromhex("0000 10 01") + bytes.fromhex("0100 40 00"))
    assert len(rep.records) == 1 and rep.records[0].value is True


def test_start_up_on_off_decodes_to_power_on_behavior():
    from oneroof_zigbee.zcl import decode_attributes
    assert decode_attributes(0x0006, [(0x4003, None)]) == {"power_on_behavior": "previous"}   # 0xFF → None → previous
    assert decode_attributes(0x0006, [(0x4003, 2), (0, True)]) == {"state": "ON", "power_on_behavior": "toggle"}
