"""User device definitions: storage, precedence over the built-in table, validation, export/import,
the UI API and the discovery re-announce that follows a change."""

from __future__ import annotations

import asyncio
import json

import pytest
import yaml

from oneroof_zigbee import quirks
from oneroof_zigbee.definitions import Definitions, validate_definition
from oneroof_zigbee.devices import Device, Endpoint
from oneroof_zigbee.zcl import vendor as vz
from tests.test_quirks_tuya import B, E, V, _dp, _val, ha, keys, mk, report
from tests.test_ui import http, ui  # noqa: F401  (fixture)

IEEE = 0x00158D0000000021
NWK = 0x2345


@pytest.fixture(autouse=True)
def _isolated_definitions():
    yield
    quirks.set_definitions(None)


SOIL = {"kind": "Soil sensor", "category": "sensor", "datapoints": [
    {"dp": 3, "key": "soil_moisture", "name": "Soil moisture", "unit": "%", "device_class": "moisture", "min": 0, "max": 100},
    {"dp": 5, "key": "temperature", "scale": 10, "unit": "°C", "device_class": "temperature"},
    {"dp": 15, "key": "battery", "unit": "%", "category": "diagnostic", "device_class": "battery"},
    {"dp": 7, "key": "child_lock", "type": "binary", "access": "rw", "values": {0: "UNLOCK", 1: "LOCK"}, "category": "config"},
    {"dp": 9, "key": "unit", "type": "enum", "access": "rw", "values": {0: "celsius", 1: "fahrenheit"}, "category": "config"},
    {"dp": 101, "key": "sleeping", "type": "binary", "inverted": True},
]}


def test_storage_round_trip_and_file_mode(tmp_path):
    path = tmp_path / "definitions.yaml"
    defs = Definitions(path)
    saved = defs.put("_TZE200_soilzzzz", "TS0601", SOIL)
    assert saved["manufacturer"] == "_TZE200_soilzzzz" and [d["dp"] for d in saved["datapoints"]] == [3, 5, 7, 9, 15, 101]
    assert saved["datapoints"][0]["name"] == "Soil moisture" and saved["datapoints"][1]["name"] == "Temperature"  # name defaults from key
    dt = {d["dp"]: d["dtype"] for d in saved["datapoints"]}
    assert dt[7] == "bool" and dt[9] == "enum" and dt[3] == "value"  # wire type defaults from the feature type
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    again = Definitions(path)
    assert again.all() == defs.all() and again.get("_TZE200_SOILZZZZ", "ts0601") == saved
    assert again.find("_tze200_soilzzzz", "TS0601") == saved and again.find("_TZE200_other", "TS0601") is None
    assert again.delete("_TZE200_soilzzzz", "TS0601") and not again.delete("_TZE200_soilzzzz", "TS0601")
    assert Definitions(path).all() == []


def test_patterns_match_every_device_of_the_model(tmp_path):
    defs = Definitions(tmp_path / "d.yaml")
    defs.put("_TZE200_*", "TS0601", {"kind": "Mystery box", "category": "sensor"})
    quirks.set_definitions(defs)
    dev = mk("_TZE200_whatever")
    assert dev.kind == "Mystery box" and dev.category == "sensor" and dev.vendor == "Tuya"
    assert mk("_TZE204_other").kind == "Tuya device (datapoints)"


def test_definition_takes_precedence_over_builtin_and_inference(tmp_path):
    defs = Definitions(tmp_path / "d.yaml")
    quirks.set_definitions(defs)
    # 1. a model the built-in table knows: the user's datapoint replaces the built-in one with the same id, the rest stays
    trv = mk("_TZE200_ckud7u2l")
    before = [d.key for d in quirks.tuya_dps(trv)]
    assert "current_heating_setpoint" in before
    defs.put("_TZE200_ckud7u2l", "TS0601", {"datapoints": [{"dp": 2, "key": "target", "name": "Target", "access": "rw", "scale": 10, "unit": "°C"},
                                                              {"dp": 200, "key": "extra", "type": "binary"}], "remove": ["child_lock"]})
    q = quirks.find_quirk("_TZE200_ckud7u2l", "TS0601")
    assert q.user_defined and q.kind == "Thermostat/TRV" and q.bind == ()  # inherited from the built-in entry
    after = [d.key for d in quirks.tuya_dps(trv)]
    assert "target" in after and "current_heating_setpoint" not in after and "extra" in after and "child_lock" not in after
    assert "local_temperature" in after
    assert quirks.decode_tuya_report(trv, vz.TUYA_CMD_DATA_REPORT, b"\x00\x01" + _dp(2, V, _val(215)) + _dp(200, B, b"\x01")) == {"target": 21.5, "extra": True}
    # 2. an unknown model whose reports would be *inferred* as a thermostat: the definition wins
    dev = mk("_TZE200_soilzzzz")
    report(dev, (3, V, _val(41)), (5, V, _val(236)))
    assert dev.kind == "Soil sensor"  # inferred (soil family) so far
    defs.put("_TZE200_soilzzzz", "TS0601", SOIL)
    assert dev.kind == "Soil sensor" and dev.category == "sensor"
    st = report(dev, (3, V, _val(41)), (5, V, _val(236)), (7, B, b"\x01"), (9, E, b"\x01"), (101, B, b"\x01"), (33, V, _val(9)))
    assert st == {"soil_moisture": 41, "temperature": 23.6, "child_lock": "LOCK", "unit": "fahrenheit", "sleeping": False, "dp_33": 9}
    k = keys(dev)
    assert "inferred" not in k["soil_moisture"] and k["soil_moisture"]["device_class"] == "moisture" and k["dp_33"]["type"] == "numeric"
    assert k["child_lock"]["category"] == "config" and k["child_lock"]["access"] == "rw"
    h = ha(dev)
    assert h["soil_moisture"][0] == "sensor" and h["soil_moisture"][1]["device_class"] == "moisture"
    assert h["child_lock"][0] == "lock" and h["unit"][0] == "select" and h["unit"][1]["options"] == ["celsius", "fahrenheit"]
    assert quirks.encode_tuya_command(dev, "unit", "celsius", 4) == b"\x00\x04" + _dp(9, E, b"\x00")
    assert quirks.encode_tuya_command(dev, "child_lock", "LOCK", 5) == b"\x00\x05" + _dp(7, B, b"\x01")
    # 3. the definition can be deleted again: back to inference
    defs.delete("_TZE200_soilzzzz", "TS0601")
    assert "inferred" in keys(dev)["soil_moisture"]


def test_on_off_as_and_kind_override_for_plain_zigbee_models(tmp_path):
    defs = Definitions(tmp_path / "d.yaml")
    quirks.set_definitions(defs)
    dev = Device(ieee=IEEE, nwk=NWK, friendly_name="x", manufacturer="Acme", model="Magnet-1", power_source="mains")
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0x0000, 0x0001, 0x0006], [])
    assert "state" in keys(dev) and dev.kind == "Switch"
    defs.put("Acme", "Magnet-1", {"kind": "Contact sensor", "category": "sensor", "vendor": "Acme Inc", "on_off_as": "contact", "remove": ["identify"]})
    assert dev.kind == "Contact sensor" and dev.vendor == "Acme Inc"
    k = keys(dev)
    assert "contact" in k and "state" not in k
    assert quirks.translate_state(dev, 1, {"state": "OFF"}) == {"contact": True}
    assert ha(dev)["contact"][1]["device_class"] == "door"


@pytest.mark.parametrize("manufacturer,model,body,msg", [
    ("", "TS0601", {}, "manufacturer"),
    ("_TZE200_x", "bad model", {}, "model"),
    ("_TZE200_x", "TS0601", {"kind": 5}, "kind"),
    ("_TZE200_x", "TS0601", {"category": "spaceship"}, "category"),
    ("_TZE200_x", "TS0601", {"bogus": 1}, "unknown field"),
    ("_TZE200_x", "TS0601", {"remove": ["Bad Key"]}, "remove"),
    ("_TZE200_x", "TS0601", {"datapoints": "x"}, "datapoints"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 0, "key": "a"}]}, "dp"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 300, "key": "a"}]}, "dp"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "Temp"}]}, "key"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "dp_1"}]}, "reserved"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "type": "float"}]}, "type"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "access": "x"}]}, "access"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "scale": 0}]}, "scale"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "scale": "ten"}]}, "scale"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "type": "enum"}]}, "values"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "values": {"x": "y"}}]}, "values"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "dtype": "float"}]}, "dtype"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "inverted": "yes"}]}, "inverted"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "device_class": "Door!"}]}, "device_class"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "category": "other"}]}, "category"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "min": 5, "max": 1}]}, "min"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a", "nope": 1}]}, "unknown datapoint field"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a"}, {"dp": 1, "key": "b"}]}, "twice"),
    ("_TZE200_x", "TS0601", {"datapoints": [{"dp": 1, "key": "a"}, {"dp": 2, "key": "a"}]}, "twice"),
])
def test_validation_rejects(manufacturer, model, body, msg):
    with pytest.raises(ValueError, match=msg):
        validate_definition(manufacturer, model, body)


def test_validation_normalises():
    d = validate_definition(" _TZE200_x ", "TS0601", {"datapoints": [{"dp": "7", "key": "lock", "type": "binary", "values": [False, True], "dtype": 1}]})
    assert d["datapoints"][0] == {"dp": 7, "key": "lock", "name": "Lock", "type": "binary", "access": "r", "category": "sensor", "values": {0: "false", 1: "true"}, "dtype": "bool"}


def test_export_import_and_unreadable_file(tmp_path):
    defs = Definitions(tmp_path / "d.yaml")
    defs.put("_TZE200_soilzzzz", "TS0601", SOIL)
    text = defs.export_yaml()
    data = yaml.safe_load(text)
    assert data["definitions"][0]["model"] == "TS0601" and data["definitions"][0]["datapoints"][0]["key"] == "soil_moisture"
    other = Definitions(tmp_path / "e.yaml")
    assert [d["manufacturer"] for d in other.import_yaml(text)] == ["_TZE200_soilzzzz"]
    assert other.all() == defs.all()
    # all-or-nothing: one bad entry rejects the whole file and leaves the store untouched
    bad = text + "\n- manufacturer: _TZE200_bad\n  model: TS0601\n  datapoints:\n    - dp: 999\n      key: x\n"
    with pytest.raises(ValueError, match="entry 2"):
        other.import_yaml(bad)
    assert len(other.all()) == 1
    with pytest.raises(ValueError, match="YAML"):
        other.import_yaml("definitions: [\n")
    with pytest.raises(ValueError, match="list"):
        other.import_yaml("definitions: 7")
    # replace mode drops what was there
    other.import_yaml("definitions:\n- manufacturer: Acme\n  model: Thing\n  kind: Box\n", replace_all=True)
    assert [d["manufacturer"] for d in other.all()] == ["Acme"]
    # a damaged file on disk is skipped entry by entry, never crashes
    (tmp_path / "f.yaml").write_text("definitions:\n- manufacturer: ok\n  model: m\n- manufacturer: ''\n  model: m\n- 5\n")
    assert [d["manufacturer"] for d in Definitions(tmp_path / "f.yaml").all()] == ["ok"]
    (tmp_path / "g.yaml").write_text("{{{")
    assert Definitions(tmp_path / "g.yaml").all() == []


# ---------------------------------------------------------------------------------------------
# Through the UI API and the gateway
# ---------------------------------------------------------------------------------------------


async def _add_tuya_device(gw, manufacturer="_TZE200_apizzzzz"):
    dev = gw.registry.add_or_update(IEEE, NWK, manufacturer=manufacturer, model="TS0601", power_source="battery", interviewed=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0x0000, 0x0004, 0x0005, 0xEF00], [0x0019, 0x000A])
    await gw._announce(dev)
    return dev


def _report(*dps):
    return bytes([0x09, 0x31, 0x02]) + b"\x00\x01" + b"".join(_dp(d, t, v) for d, t, v in dps)


async def test_api_definitions_flow_and_reannounce(ui):  # noqa: F811
    fake, gw, server, api = ui
    port = server.port
    broker = gw.broker
    dev = await _add_tuya_device(gw)
    topic = f"oneroof/zigbee/{dev.ieee_str}"
    # reports arrive: the gateway records what it saw, exposes raw datapoints and announces them
    fake.emit_incoming(NWK, 0xEF00, _report((3, V, _val(41)), (5, V, _val(236)), (33, V, _val(9))))
    await asyncio.sleep(0.05)
    st = json.loads(broker.last(f"{topic}/state"))
    assert st["soil_moisture"] == 41 and st["temperature"] == 23.6 and st["dp_33"] == 9  # inferred soil family + raw leftover
    assert dev.context["tuya_seen"]["33"] == {"type": V, "last": 9, "ts": dev.context["tuya_seen"]["33"]["ts"]}
    assert broker.last(f"homeassistant/sensor/{dev.ieee_str}/dp_33/config") not in (None, b"")
    st_, _, body = await http(port, "GET", f"/api/devices/{dev.ieee_str}/datapoints")
    dpi = json.loads(body)
    assert st_ == 200 and dpi["source"] == "inferred" and dpi["family"] == "soil" and dpi["has_datapoints"] is True
    assert [r["dp"] for r in dpi["datapoints"]] == [3, 5, 33] and dpi["datapoints"][0]["key"] == "soil_moisture" and dpi["datapoints"][0]["inferred"] is True
    assert dpi["datapoints"][2]["key"] is None and dpi["datapoints"][2]["type_name"] == "value" and dpi["datapoints"][2]["last"] == 9
    # the device detail marks inferred features
    _, _, body = await http(port, "GET", f"/api/devices/{dev.ieee_str}")
    ex = {f["key"]: f for f in json.loads(body)["exposes"]}
    assert ex["soil_moisture"]["inferred"] is True and "inferred" not in ex["dp_33"]

    # teach it: dp 33 becomes "weight", kind is overridden
    defn = {"kind": "Plant monitor", "category": "sensor", "datapoints": SOIL["datapoints"] + [{"dp": 33, "key": "weight", "unit": "g", "scale": 1}]}
    st_, _, body = await http(port, "PUT", "/api/definitions/_TZE200_apizzzzz/TS0601", defn)
    r = json.loads(body)
    assert st_ == 200 and r["ok"] and r["devices"] == [dev.ieee_str] and r["definition"]["kind"] == "Plant monitor"
    assert (gw.cfg.data_dir / "definitions.yaml").exists()
    # state rebuilt from the last seen values, stale raw key dropped, entity for dp_33 removed, new ones announced
    st = json.loads(broker.last(f"{topic}/state"))
    assert st["weight"] == 9 and "dp_33" not in st and st["soil_moisture"] == 41
    assert broker.last(f"homeassistant/sensor/{dev.ieee_str}/dp_33/config") == b""
    assert json.loads(broker.last(f"homeassistant/sensor/{dev.ieee_str}/weight/config"))["unit_of_measurement"] == "g"
    assert json.loads(broker.last("oneroof/zigbee/bridge/devices"))[0]["kind"] == "Plant monitor"
    assert dev.kind == "Plant monitor"
    _, _, body = await http(port, "GET", f"/api/devices/{dev.ieee_str}/datapoints")
    dpi = json.loads(body)
    assert dpi["source"] == "definition" and dpi["datapoints"][2]["key"] == "weight" and dpi["datapoints"][2]["inferred"] is False
    assert dpi["definition"]["kind"] == "Plant monitor"
    # subsequent reports use the taught keys; the device page shows no "inferred" tag any more
    fake.emit_incoming(NWK, 0xEF00, _report((33, V, _val(12)), (7, B, b"\x01")))
    await asyncio.sleep(0.05)
    st = json.loads(broker.last(f"{topic}/state"))
    assert st["weight"] == 12 and st["child_lock"] == "LOCK"
    _, _, body = await http(port, "GET", f"/api/devices/{dev.ieee_str}")
    assert "inferred" not in {f["key"]: f for f in json.loads(body)["exposes"]}["soil_moisture"]
    # a command goes out as setData with the user's wire type
    fake.requests.clear()
    st_, _, body = await http(port, "POST", f"/api/devices/{dev.ieee_str}/set", {"child_lock": "UNLOCK"})
    assert st_ == 200
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1 and reqs[0].data[10:][5:] == _dp(7, B, b"\x00")

    # list / export / import / delete
    st_, _, body = await http(port, "GET", "/api/definitions")
    lst = json.loads(body)
    assert st_ == 200 and len(lst["definitions"]) == 1 and lst["definitions"][0]["model"] == "TS0601" and "categories" in lst["options"]
    st_, h, body = await http(port, "GET", "/api/definitions/export")
    assert st_ == 200 and h["Content-Type"].startswith("application/yaml") and yaml.safe_load(body)["definitions"][0]["kind"] == "Plant monitor"
    exported = body.decode()
    st_, _, body = await http(port, "DELETE", "/api/definitions/_TZE200_apizzzzz/TS0601", {})
    assert st_ == 200 and json.loads(body)["devices"] == [dev.ieee_str] and gw.definitions.all() == []
    assert dev.kind == "Soil sensor"  # back to inference
    assert "weight" not in json.loads(broker.last(f"{topic}/state")) and broker.last(f"homeassistant/sensor/{dev.ieee_str}/weight/config") == b""
    st_, _, body = await http(port, "DELETE", "/api/definitions/_TZE200_apizzzzz/TS0601", {})
    assert st_ == 404
    st_, _, body = await http(port, "POST", "/api/definitions/import", {"yaml": exported})
    assert st_ == 200 and json.loads(body)["imported"] == 1 and dev.kind == "Plant monitor"
    st_, _, body = await http(port, "POST", "/api/definitions/import", {"yaml": "definitions:\n- manufacturer: x\n  model: y\n  category: nope\n"})
    assert st_ == 400 and "category" in json.loads(body)["error"]
    # a definition restored from file survives a fresh Definitions instance (the gateway reads it at start)
    assert Definitions(gw.cfg.data_dir / "definitions.yaml").all()[0]["kind"] == "Plant monitor"


async def test_api_definitions_validation_csrf_and_control_gate(ui):  # noqa: F811
    fake, gw, server, api = ui
    port = server.port
    st, _, body = await http(port, "PUT", "/api/definitions/_TZE200_x/TS0601", {"datapoints": [{"dp": 1, "key": "Bad"}]})
    assert st == 400 and "key" in json.loads(body)["error"]
    st, _, body = await http(port, "PUT", "/api/definitions/_TZE200_x/TS0601", {"bogus": 1})
    assert st == 400 and "unknown field" in json.loads(body)["error"]
    # PUT / DELETE need the same CSRF header as POST
    st, _, _ = await http(port, "PUT", "/api/definitions/_TZE200_x/TS0601", headers={"Content-Type": "application/json"}, raw_body=b"{}")
    assert st == 403
    st, _, _ = await http(port, "DELETE", "/api/definitions/_TZE200_x/TS0601", headers={}, raw_body=b"")
    assert st == 403
    # non-control users may read but not change
    api.acts_as = "homeassistant"
    st, _, _ = await http(port, "GET", "/api/definitions")
    assert st == 200
    st, _, body = await http(port, "PUT", "/api/definitions/_TZE200_x/TS0601", {"kind": "X"})
    assert st == 403 and "not authorized" in json.loads(body)["error"]
    st, _, _ = await http(port, "POST", "/api/definitions/import", {"yaml": "definitions: []"})
    assert st == 403
    st, _, _ = await http(port, "DELETE", "/api/definitions/_TZE200_x/TS0601", {})
    assert st == 403
    assert gw.definitions.all() == []


async def test_kind_override_for_a_plain_zigbee_device_reannounces(ui):  # noqa: F811
    fake, gw, server, api = ui
    port = server.port
    broker = gw.broker
    dev = gw.registry.add_or_update(IEEE, NWK, manufacturer="Acme", model="Magnet-1", power_source="mains", interviewed=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0x0000, 0x0001, 0x0006], [])
    await gw._announce(dev)
    assert broker.last(f"homeassistant/switch/{dev.ieee_str}/switch/config") not in (None, b"")
    st, _, body = await http(port, "PUT", "/api/definitions/Acme/Magnet-1", {"kind": "Contact sensor", "category": "sensor", "on_off_as": "contact"})
    assert st == 200 and json.loads(body)["devices"] == [dev.ieee_str]
    assert broker.last(f"homeassistant/switch/{dev.ieee_str}/switch/config") == b""
    assert json.loads(broker.last(f"homeassistant/binary_sensor/{dev.ieee_str}/contact/config"))["device_class"] == "door"
    assert dev.kind == "Contact sensor"
    # no layout change → no refresh (a second identical save is a no-op for devices)
    st, _, body = await http(port, "PUT", "/api/definitions/Acme/Magnet-1", {"kind": "Contact sensor", "category": "sensor", "on_off_as": "contact"})
    assert st == 200 and json.loads(body)["devices"] == []


def test_gateway_installs_definitions_process_wide(tmp_path):
    (tmp_path / "definitions.yaml").write_text("definitions:\n- manufacturer: _TZE200_boot\n  model: TS0601\n  kind: Boot box\n")
    from tests.test_gateway import FakeBroker
    from oneroof_zigbee.config import Config
    from oneroof_zigbee.devices import Registry
    from oneroof_zigbee.gateway import Gateway
    from oneroof_zigbee.security import Audit
    cfg = Config.from_dict({"serial": {"port": "/dev/null"}, "data_dir": str(tmp_path)})
    gw = Gateway(cfg, None, FakeBroker(), Audit(tmp_path / "audit.log"), Registry(None))
    assert gw.definitions.all()[0]["kind"] == "Boot box"
    assert mk("_TZE200_boot").kind == "Boot box"
