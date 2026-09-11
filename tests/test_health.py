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
    assert r["counts"] == {"offline": 1, "weak_link": 1, "flapping": 1, "quiet": 2, "busy_router": 0}
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
