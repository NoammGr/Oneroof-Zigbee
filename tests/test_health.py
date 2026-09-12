"""Is my network healthy? Findings that name a device and say why, and the family's health line."""
from oneroof_zigbee.health import best_parents, health_line, network_health

C = "0x00124b0000000000"
DEVS = [
    {"ieee": C, "name": "Coordinator", "kind": "coordinator", "available": True, "last_seen": 1e6},
    {"ieee": "0x00158d0000000001", "name": "Garage - Smart Plug", "kind": "router", "available": False, "last_seen": 1e6 - 100},
    {"ieee": "0x00158d0000000002", "name": "Hall - Lamp", "kind": "router", "available": True, "last_seen": 1e6 - 100},
    {"ieee": "0x00158d0000000003", "name": "Stairs - Bulb", "kind": "router", "available": True, "last_seen": 1e6 - 100},
    {"ieee": "0x00158d0000000004", "name": "Garage - Door", "kind": "end_device", "available": True, "last_seen": 1e6 - 30 * 3600, "battery": True},
    {"ieee": "0x00158d0000000005", "name": "Kitchen - Kettle plug", "kind": "router", "available": True, "last_seen": 1e6 - 7 * 3600},
]
LINKS = [
    {"source": C, "target": "0x00158d0000000002", "lqi": 200},
    {"source": C, "target": "0x00158d0000000003", "lqi": 45},
    {"source": "0x00158d0000000002", "target": "0x00158d0000000003", "lqi": 70},   # the better of its two hops, still weak
    {"source": "0x00158d0000000002", "target": "0x00158d0000000004", "lqi": 180},
    {"source": "0x00158d0000000005", "target": "0x00158d0000000002", "lqi": 120},
]


def test_best_parents_take_the_strongest_hop_to_a_relay():
    p = best_parents(DEVS, LINKS)
    assert p["0x00158d0000000003"] == ("0x00158d0000000002", 70)
    assert p["0x00158d0000000004"] == ("0x00158d0000000002", 180)
    assert p["0x00158d0000000002"] == (C, 200)
    assert C not in p                                     # the coordinator talks through nobody


def test_findings_name_the_device_and_say_why():
    flaps = {"0x00158d0000000001": [1e6 - t for t in (100, 3000, 6000, 9000, 90000)]}   # 4 within a day, 1 older
    r = network_health(DEVS, LINKS, flaps, now=1e6)
    kinds = {(f["kind"], f["name"]) for f in r["findings"]}
    assert ("offline", "Garage - Smart Plug") in kinds
    assert ("flapping", "Garage - Smart Plug") in kinds
    assert ("weak_link", "Stairs - Bulb") in kinds
    assert ("quiet", "Garage - Door") in kinds            # a battery device silent 30 h
    assert ("quiet", "Kitchen - Kettle plug") in kinds    # mains silent 7 h
    assert ("quiet", "Hall - Lamp") not in kinds
    weak = next(f for f in r["findings"] if f["kind"] == "weak_link")
    assert "Hall - Lamp" in weak["detail"] and "LQI 70" in weak["detail"] and weak["severity"] == "warn"
    flap = next(f for f in r["findings"] if f["kind"] == "flapping")
    assert "4 times" in flap["detail"]
    assert r["verdict"] == "bad" and r["walked"] and r["devices"] == 5
    assert r["counts"] == {"offline": 1, "weak_link": 1, "flapping": 1, "quiet": 2, "busy_router": 0, "battery": 0, "wall_off": 0, "wall_hint": 0}
    # the worst first, then by name
    assert [f["severity"] for f in r["findings"]] == sorted((f["severity"] for f in r["findings"]), key=lambda s: s != "bad")


def test_without_a_walk_links_are_not_judged_and_a_healthy_net_is_ok():
    fine = [dict(d, available=True, last_seen=1e6 - 60) for d in DEVS]
    r = network_health(fine, [], {}, now=1e6)
    assert r["verdict"] == "ok" and r["findings"] == [] and r["walked"] is False


def test_a_router_carrying_too_many_children_is_called_out():
    devs = [DEVS[0], DEVS[2]] + [{"ieee": f"0x00158d00000000{i:02x}", "name": f"Sensor {i}", "kind": "end_device",
                                  "available": True, "last_seen": 1e6, "battery": True} for i in range(16, 28)]
    links = [{"source": "0x00158d0000000002", "target": d["ieee"], "lqi": 200} for d in devs[2:]]
    r = network_health(devs, links, {}, now=1e6)
    busy = [f for f in r["findings"] if f["kind"] == "busy_router"]
    assert busy and busy[0]["name"] == "Hall - Lamp" and "12 devices" in busy[0]["detail"]


def test_the_health_line_is_the_family_shape():
    r = network_health(DEVS, LINKS, {}, now=1e6)
    line = health_line(r, "2.18.0", 4242, True)
    assert line["status"] == "degraded" and line["version"] == "2.18.0" and line["uptime_s"] == 4242
    assert line["reasons"] == ["1 device offline", "1 weak link", "2 quiet"]
    assert line["coordinator"] == "ok" and line["devices"] == 5 and line["offline"] == 1
    fine = [dict(d, available=True, last_seen=1e6 - 60) for d in DEVS]
    line = health_line(network_health(fine, [], {}, now=1e6), "2.18.0", 1, False)
    assert line["status"] == "degraded" and line["reasons"] == ["coordinator offline"]
    line = health_line(network_health(fine, [], {}, now=1e6), "2.18.0", 1, True)
    assert line["status"] == "ok" and line["reasons"] == []


def test_battery_forecast_is_a_line_through_the_readings_and_honest_about_thin_data():
    from oneroof_zigbee.health import battery_forecast
    day = 86400
    now = 1e6
    assert battery_forecast(None, now) is None
    assert battery_forecast([[now - day, 90]], now)["confidence"] == "none"                       # one reading
    assert battery_forecast([[now - 2 * day, 90], [now - day, 89], [now, 88]], now)["days_left"] is None   # two days: too soon
    # 1 % a day for three weeks: from 79 % to the 10 % floor in about 69 days
    log = [[now - (21 - i) * day, 100 - i] for i in range(22)]
    fc = battery_forecast(log, now)
    assert fc["pct"] == 79 and fc["confidence"] == "ok" and abs(fc["per_day"] + 1.0) < 0.01 and 68 <= fc["days_left"] <= 70
    # a week of history: a forecast, but marked as an early guess
    fc = battery_forecast(log[-8:], now)
    assert fc["confidence"] == "low" and fc["days_left"] is not None
    # flat or charging: no forecast
    flat = [[now - (21 - i) * day, 100] for i in range(22)]
    assert battery_forecast(flat, now)["days_left"] is None


def test_a_battery_about_to_run_out_is_a_finding_and_a_reason():
    day = 86400
    now = 1e6
    dying = [[now - (20 - i) * day, 40 - i * 1.5] for i in range(21)]        # 1.5 %/day, now at 10 %
    devs = [DEVS[0], dict(DEVS[4], last_seen=now - 60, battery_log=dying, battery_pct=10),
            {"ieee": "0x00158d0000000009", "name": "Kitchen - Leak sensor", "kind": "end_device", "available": True,
             "last_seen": now - 60, "battery": True, "battery_pct": 14},
            {"ieee": "0x00158d000000000a", "name": "Hall - Motion", "kind": "end_device", "available": True,
             "last_seen": now - 60, "battery": True, "battery_log": [[now - (20 - i) * day, 60 - i] for i in range(21)]}]
    r = network_health(devs, [], {}, now=now)
    by = {f["name"]: f for f in r["findings"] if f["kind"] == "battery"}
    assert by["Garage - Door"]["severity"] == "bad" and "time for a new one" in by["Garage - Door"]["detail"]
    assert by["Kitchen - Leak sensor"]["severity"] == "warn"                       # 14 %, no history: still low
    assert "Hall - Motion" not in by                                              # 40 % and a month to go
    assert r["counts"]["battery"] == 2
    assert "2 batteries to replace" in health_line(r, "x", 1, True)["reasons"]


def test_a_device_behind_a_wall_switch_is_off_not_a_problem():
    now = 1e6
    bulb = {"ieee": "0x00158d0000000011", "name": "Stairs - Bulb", "kind": "router", "available": True, "last_seen": now - 9 * 3600,
            "wall_switched": True, "wall_off": True}
    sensor = {"ieee": "0x00158d0000000012", "name": "Landing - Motion", "kind": "end_device", "available": True, "last_seen": now - 60, "battery": True}
    suspect = {"ieee": "0x00158d0000000013", "name": "Hall - Lamp", "kind": "router", "available": False, "last_seen": now - 7200, "wall_pattern": 3}
    devs = [DEVS[0], bulb, sensor, suspect]
    links = [{"source": "0x00158d0000000011", "target": "0x00158d0000000012", "lqi": 40}]   # its child, on a weak hop
    flaps = {"0x00158d0000000011": [now - t for t in (100, 200, 300, 400, 500)]}
    r = network_health(devs, links, flaps, now=now)
    kinds = {(f["kind"], f["name"]): f for f in r["findings"]}
    # no offline / quiet / flapping / weak-link for the bulb - it is off at the wall, and says how many it strands
    assert ("wall_off", "Stairs - Bulb") in kinds and "1 device lose" in kinds[("wall_off", "Stairs - Bulb")]["detail"]
    assert not any(k[1] == "Stairs - Bulb" and k[0] != "wall_off" for k in kinds)
    # the lamp that went silent while ON three times gets the hint, and is still offline for real
    assert ("wall_hint", "Hall - Lamp") in kinds and ("offline", "Hall - Lamp") in kinds
    # info lines do not colour the verdict; the real offline does
    assert r["verdict"] == "bad" and r["counts"]["wall_off"] == 1 and r["counts"]["wall_hint"] == 1
    only_wall = network_health([DEVS[0], bulb], links, {}, now=now)
    assert only_wall["verdict"] == "ok" and health_line(only_wall, "x", 1, True)["status"] == "ok"
