"""The exposes description other One Roof apps build their accessories from."""

from __future__ import annotations

from oneroof_zigbee.devices import Device, Endpoint
from oneroof_zigbee.ha.exposes import ACCESS_GET, ACCESS_SET, ACCESS_STATE, device_description, exposes_for


def mk(ieee, manu, model, eps, router=True, **kw):
    d = Device(ieee=ieee, nwk=0x1000 + (ieee & 0xFF), friendly_name=f"dev{ieee & 0xFF}", manufacturer=manu, model=model, is_router=router)
    for ep, (ins, outs, did) in eps.items():
        d.endpoints[ep] = Endpoint(ep, 0x0104, did, ins, outs, "unknown")
    d.interviewed = True
    for k, v in kw.items():
        setattr(d, k, v)
    return d


def by_type(exposes):
    return {e["type"]: e for e in exposes if "features" in e}


def test_light_switch_gangs_cover_climate_lock():
    bulb = mk(0x54EF440000000002, "Aqara", "lumi.light.acn014", {1: ([0, 3, 4, 5, 6, 8, 0x300], [], 0x010C)})
    light = by_type(exposes_for(bulb))["light"]
    props = {f["property"]: f for f in light["features"]}
    assert props["state"]["value_on"] == "ON" and props["state"]["value_toggle"] == "TOGGLE" and props["state"]["access"] == 7
    assert props["brightness"]["value_max"] == 254 and props["color_temp"]["unit"] == "mired"
    assert props["color"]["type"] == "composite" and {f["property"] for f in props["color"]["features"]} == {"x", "y"}

    sw = mk(0x54EF440000000001, "LUMI", "lumi.switch.b2lc04", {1: ([0, 3, 4, 5, 6, 0xFCC0], [], 0x0100), 2: ([4, 5, 6], [], 0x0100)}, router=False)
    switches = [e for e in exposes_for(sw) if e["type"] == "switch"]
    assert [(e["endpoint"], e["features"][0]["property"]) for e in switches] == [("left", "state_left"), ("right", "state_right")]
    action = next(e for e in exposes_for(sw) if e.get("property") == "action")
    assert action["type"] == "enum" and action["access"] == ACCESS_STATE and action["values"]

    cover = mk(0x00158D0000000021, "LUMI", "lumi.curtain", {1: ([0, 3, 4, 5, 0x0102], [], 0x0202)})
    cv = by_type(exposes_for(cover))["cover"]
    fp = {f["property"]: f for f in cv["features"]}
    assert set(fp["state"]["values"]) == {"OPEN", "CLOSE", "STOP"} and fp["position"]["value_max"] == 100

    trv = mk(0xA4C1380000000031, "_TZE200_ckud7u2l", "TS0601", {1: ([0, 4, 5, 0xEF00], [], 0x0051)}, router=False)
    cl = by_type(exposes_for(trv))["climate"]
    cp = {f["property"]: f for f in cl["features"]}
    assert cp["current_heating_setpoint"]["access"] == 7 and "local_temperature" in cp

    lock = mk(0x00178B0000000001, "Yale", "YRD226", {1: ([0, 1, 3, 9, 0x0101], [], 0x000A)}, router=False)
    lk = by_type(exposes_for(lock))["lock"]
    assert lk["features"][0]["value_on"] == "LOCK" and lk["features"][0]["value_off"] == "UNLOCK"


def test_sensors_and_description_shape():
    door = mk(0x00158D0000000001, "LUMI", "lumi.sensor_magnet.aq2", {1: ([0, 3, 0xFFFF], [0, 4, 3, 6, 8, 5], 0x0104)}, router=False)
    desc = device_description(door)
    assert desc["ieee_address"] == door.ieee_str and desc["type"] == "EndDevice" and desc["supported"] is True
    d = desc["definition"]
    assert d["vendor"] and d["model"] == "lumi.sensor_magnet.aq2" and d["description"] == "Contact sensor"
    props = {e["property"]: e for e in d["exposes"] if "property" in e}
    assert props["contact"]["type"] == "binary" and props["contact"]["access"] == ACCESS_STATE and props["contact"]["value_on"] is True
    assert props["battery"]["type"] == "numeric" and props["battery"]["unit"] == "%"
    assert "linkquality" in props
    # nothing settable on a sensor
    assert all(not (e["access"] & ACCESS_SET) for e in props.values()), props
    # access bit semantics
    assert ACCESS_STATE | ACCESS_SET | ACCESS_GET == 7
