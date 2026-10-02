import asyncio
import base64
import json
import struct

import pytest

from oneroof_zigbee import importer
from oneroof_zigbee.ota import NO_IMAGE_AVAILABLE, SUCCESS, OtaError, OtaServer, parse_image
from oneroof_zigbee.security import Audit, NetworkSecrets
from tests.test_ui import IEEE, NWK, http, pair_one, ui  # noqa: F401,F811  (fixture reuse)


def make_ota(manuf=0x1037, itype=0x0001, version=0x00000005, body=b"\xAB" * 300, wrapper=b"") -> bytes:
    hstr = b"OneRoof test image".ljust(32, b"\x00")
    total = 56 + len(body)
    hdr = struct.pack("<IHHHHHIH", 0x0BEEF11E, 0x0100, 56, 0, manuf, itype, version, 2) + hstr + struct.pack("<I", total)
    return wrapper + hdr + body


def test_parse_ota_header_and_rejections(tmp_path):
    p = tmp_path / "a.ota"
    p.write_bytes(make_ota())
    img = parse_image(p)
    assert img.manufacturer == 0x1037 and img.image_type == 1 and img.file_version == 5 and img.total_size == 356
    assert img.header_string == "OneRoof test image" and len(img.sha256) == 64
    (tmp_path / "wrapped.ota").write_bytes(make_ota(wrapper=b"VENDORHDR" * 3))
    assert parse_image(tmp_path / "wrapped.ota").total_size == 356
    (tmp_path / "bad.bin").write_bytes(b"not firmware")
    with pytest.raises(OtaError):
        parse_image(tmp_path / "bad.bin")
    (tmp_path / "trunc.ota").write_bytes(make_ota()[:-10])
    with pytest.raises(OtaError, match="does not match"):
        parse_image(tmp_path / "trunc.ota")


def test_ota_server_policy(tmp_path):
    srv = OtaServer(tmp_path / "fw", Audit(None))
    srv.add_image("plug_v5.ota", make_ota(version=5))
    # device queries on its own: nothing armed → no image
    q = struct.pack("<BHHI", 0, 0x1037, 1, 3)
    cmd, body = srv.handle(1, 0x1111, 1, 0x01, q)
    assert cmd == 0x02 and body[0] == NO_IMAGE_AVAILABLE
    # wrong manufacturer cannot be armed
    srv.last_query[1] = {"manufacturer": 0x9999, "image_type": 1, "file_version": 3}
    with pytest.raises(OtaError, match="manufacturer"):
        srv.arm(1, "plug_v5.ota", "ui:admin")
    # same version = downgrade/no-op refused
    srv.last_query[1] = {"manufacturer": 0x1037, "image_type": 1, "file_version": 5}
    with pytest.raises(OtaError, match="not newer"):
        srv.arm(1, "plug_v5.ota", "ui:admin")
    # proper arm + full transfer
    srv.last_query[1] = {"manufacturer": 0x1037, "image_type": 1, "file_version": 3}
    srv.arm(1, "plug_v5.ota", "ui:admin")
    cmd, body = srv.handle(1, 0x1111, 1, 0x01, q)
    st, m, t, v, size = struct.unpack("<BHHII", body)
    assert st == SUCCESS and v == 5 and size == 356
    received = b""
    offset = 0
    while offset < size:
        cmd, body = srv.handle(1, 0x1111, 1, 0x03, struct.pack("<BHHIIB", 0, 0x1037, 1, 5, offset, 64))
        st, m, t, v, off, n = struct.unpack_from("<BHHIIB", body, 0)
        assert st == SUCCESS and off == offset
        received += body[14:14 + n]
        offset += n
    assert received == make_ota(version=5)
    assert srv.status(1)["session"]["progress"] == 100.0
    cmd, body = srv.handle(1, 0x1111, 1, 0x06, struct.pack("<BHHI", SUCCESS, 0x1037, 1, 5))
    assert cmd == 0x07 and srv.sessions[1].result == "success" and 1 not in srv.armed
    # a block request for an image that was never armed is aborted
    cmd, body = srv.handle(2, 0x2222, 1, 0x03, struct.pack("<BHHIIB", 0, 0x1037, 1, 5, 0, 64))
    assert body[0] == 0x95


Z2M_CONFIG = """
homeassistant: true
mqtt:
  base_topic: zigbee2mqtt
advanced:
  network_key: [1, 3, 5, 7, 9, 11, 13, 15, 0, 2, 4, 6, 8, 10, 12, 13]
  pan_id: 6754
  ext_pan_id: [221, 221, 221, 221, 221, 221, 221, 221]
  channel: 11
devices:
  '0xa4c1380000000001':
    friendly_name: Workshop - Smart Plug
    description: Garage
  '0x00158d0001c0ffee':
    friendly_name: Office sensor
"""
Z2M_DB = "\n".join([
    json.dumps({"id": 1, "type": "Coordinator", "ieeeAddr": "0x00124b0011223344", "nwkAddr": 0}),
    json.dumps({"id": 2, "type": "Router", "ieeeAddr": "0xa4c1380000000001", "nwkAddr": 39107, "manufId": 4417, "manufName": "_TZ3000_ko6v90pg",
                "modelId": "TS011F", "powerSource": "Mains (single phase)", "interviewCompleted": True, "swBuildId": "1.0.5",
                "endpoints": {"1": {"profId": 260, "devId": 81, "inClusterList": [0, 3, 4, 5, 6, 1794, 2820], "outClusterList": [25]}}}),
    json.dumps({"id": 3, "type": "EndDevice", "ieeeAddr": "0x00158d0001c0ffee", "nwkAddr": 1234, "manufName": "LUMI", "modelId": "lumi.weather",
                "powerSource": "Battery", "interviewCompleted": True,
                "endpoints": {"1": {"profId": 260, "devId": 770, "inClusterList": [0, 1, 3, 1026, 1029], "outClusterList": []}}}),
    "not json at all",
])
Z2M_BACKUP = json.dumps({
    "metadata": {"format": "zigpy/open-coordinator-backup", "version": 1},
    "coordinator_ieee": "00124b0011223344", "pan_id": "1a62", "extended_pan_id": "dddddddddddddddd", "nwk_update_id": 0,
    "security_level": 5, "channel": 11, "channel_mask": [11],
    "network_key": {"key": "01030507090b0d0f00020406080a0c0d", "sequence_number": 0, "frame_counter": 123456},
    "devices": [{"nwk_address": "98c3", "ieee_address": "a4c1380000000001", "is_child": False}],
})


def test_import_plan_from_z2m_files():
    plan = importer.build_plan(configuration_yaml=Z2M_CONFIG, database_db=Z2M_DB, coordinator_backup=None)
    s = plan.summary()
    assert s["network"]["found"] and s["network"]["channel"] == 11 and s["network"]["pan_id"] == "0x1a62"
    assert s["network"]["key_is_well_known_default"] is True
    assert len(plan.devices) == 2
    plug = next(d for d in plan.devices if d.model == "TS011F")
    assert plug.friendly_name == "Workshop - Smart Plug" and plug.description == "Garage" and plug.is_router
    assert plug.endpoints[1].in_clusters == [0, 3, 4, 5, 6, 1794, 2820] and plug.endpoints[1].category == "plug"
    assert plug.nwk == 39107 and plug.power_source == "mains_(single_phase)"
    assert any("frame counter" in w for w in s["warnings"])


def test_import_plan_with_backup_and_apply(tmp_path):
    from oneroof_zigbee.devices import Registry
    plan = importer.build_plan(configuration_yaml=Z2M_CONFIG, database_db=Z2M_DB, coordinator_backup=Z2M_BACKUP)
    assert plan.network.frame_counter == 123456 and plan.network.source.startswith("coordinator_backup.json")
    assert plan.network.ext_pan_id == int.from_bytes(bytes([0xDD] * 8), "big")
    reg = Registry(tmp_path / "devices.json")
    current = NetworkSecrets.generate(15)
    secrets = importer.apply_plan(plan, reg, current)
    assert secrets.network_key == bytes.fromhex("01030507090b0d0f00020406080a0c0d")
    assert secrets.pan_id == 0x1A62 and secrets.channel == 11 and secrets.frame_counter == 123456 + 100_000
    assert secrets.tc_install_code == current.tc_install_code  # our strict-mode secret is kept
    d = reg.get(0xA4C1380000000001)
    assert d.friendly_name == "Workshop - Smart Plug" and d.interviewed and d.context["imported_from"] == "previous_setup"
    assert reg.by_name("Office sensor").model == "lumi.weather"


def test_import_rejects_garbage():
    with pytest.raises(ValueError):
        importer.build_plan(configuration_yaml="[::not yaml", database_db=None, coordinator_backup=None)
    with pytest.raises(ValueError):
        importer.build_plan(configuration_yaml=None, database_db=None, coordinator_backup='{"nope": 1}')
    plan = importer.build_plan(configuration_yaml=None, database_db="garbage\n", coordinator_backup=None)
    assert plan.devices == [] and any("no devices" in w for w in plan.warnings)


async def test_imported_device_keeps_pairing_and_gets_reporting(ui, tmp_path):  # noqa: F811
    """An imported device: known IEEE (no eviction on announce), reporting configured on first contact."""
    fake, gw, server, api = ui
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    api.admin = Admin(gw.cfg, None, PasswordFile(tmp_path / "p"), Acl(), gw.control_users)
    st, _, body = await http(server.port, "POST", "/api/import/preview", {"configuration.yaml": Z2M_CONFIG, "database.db": Z2M_DB})
    assert st == 200 and len(json.loads(body)["devices"]) == 2
    st, _, body = await http(server.port, "POST", "/api/import/apply", {"configuration.yaml": Z2M_CONFIG, "database.db": Z2M_DB})
    r = json.loads(body)
    assert st == 200 and r["devices"] == 2 and r["network_adopted"] is True and "import: network parameters" in r["restart_required"]
    assert 0xA4C1380000000001 in gw.coord.known_ieee
    # the device announces after a power cycle with the window CLOSED → must NOT be evicted
    leaves_before = sum(1 for f in fake.requests if f.subsystem.name == "ZDO" and f.command == 0x34)
    fake.emit_announce(0xA4C1380000000001, 0x98C3)
    await asyncio.sleep(0.1)
    assert sum(1 for f in fake.requests if f.subsystem.name == "ZDO" and f.command == 0x34) == leaves_before
    # first report from it triggers bind + configure reporting, not a re-interview
    fake.requests.clear()
    fake.emit_incoming(0x98C3, 0x0006, bytes([0x18, 0x01, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    for _ in range(50):
        await asyncio.sleep(0.02)
        if any(f.subsystem.name == "ZDO" and f.command == 0x21 for f in fake.requests):
            break
    assert any(f.subsystem.name == "ZDO" and f.command == 0x21 for f in fake.requests), "bind expected"
    assert not any(f.subsystem.name == "ZDO" and f.command == 0x05 for f in fake.requests), "no active-endpoint re-interview"
    st, _, body = await http(server.port, "GET", "/api/devices/0xa4c1380000000001")
    d = json.loads(body)
    assert d["friendly_name"] == "Workshop - Smart Plug" and d["state"]["state"] == "ON"


async def test_activity_feed_and_firmware_routes(ui, tmp_path):  # noqa: F811
    fake, gw, server, api = ui
    dev = await pair_one(fake, gw, server.port)
    fake.emit_incoming(NWK, 0x0006, bytes([0x18, 0x02, 0x0A, 0x00, 0x00, 0x10, 0x00]))
    await asyncio.sleep(0.05)
    st, _, body = await http(server.port, "GET", "/api/activity?n=50")
    a = json.loads(body)
    assert any(r["key"] == "state" and r["new"] == "OFF" and r["friendly_name"] == dev.friendly_name for r in a["rows"])
    assert "state" in a["keys"]
    st, _, body = await http(server.port, "GET", f"/api/activity?device={dev.ieee_str}&key=brightness")
    assert all(r["key"] == "brightness" for r in json.loads(body)["rows"])
    assert (tmp_path / "activity.log").exists()
    # firmware library
    st, _, body = await http(server.port, "POST", "/api/firmware/upload", {"filename": "../evil/plug.ota", "data_b64": base64.b64encode(make_ota()).decode()})
    r = json.loads(body)
    assert st == 200 and r["image"]["file"] == "plug.ota" and r["image"]["manufacturer"] == "0x1037"
    assert (tmp_path / "firmware" / "plug.ota").exists() and not (tmp_path / "evil").exists()
    st, _, body = await http(server.port, "POST", "/api/firmware/upload", {"filename": "x.bin", "data_b64": base64.b64encode(b"junk").decode()})
    assert st == 400
    st, _, body = await http(server.port, "GET", f"/api/devices/{dev.ieee_str}/update")
    assert json.loads(body)["has_ota_client"] is True  # fake simple descriptor lists 0x0019 as out cluster
    # start: device hasn't queried yet → arm succeeds, ImageNotify goes out on the wire
    fake.requests.clear()
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/update/start", {"file": "plug.ota"})
    assert st == 200
    notify = [f for f in fake.requests if f.subsystem.name == "AF" and f.command == 0x01 and int.from_bytes(f.data[4:6], "little") == 0x0019]
    assert notify and notify[0].data[10:][2] == 0x00  # ImageNotify
    # device answers with QueryNextImage(v3) → gateway must answer SUCCESS with the image details
    fake.requests.clear()
    q = bytes([0x01, 0x07, 0x01]) + struct.pack("<BHHI", 0, 0x1037, 1, 3)
    fake.emit_incoming(NWK, 0x0019, q)
    await asyncio.sleep(0.1)
    rsp = [f for f in fake.requests if f.subsystem.name == "AF" and f.command == 0x01 and int.from_bytes(f.data[4:6], "little") == 0x0019]
    assert rsp and rsp[0].data[10:][2] == 0x02 and rsp[0].data[10:][3] == SUCCESS
    st, _, body = await http(server.port, "GET", f"/api/devices/{dev.ieee_str}/update")
    s = json.loads(body)
    assert s["session"]["file"] == "plug.ota" and s["last_query"]["file_version"] == "0x00000003"
    st, _, _ = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/update/cancel", {})
    assert st == 200 and json.loads((await http(server.port, "GET", f"/api/devices/{dev.ieee_str}/update"))[2])["armed"] is None


def test_import_without_database_uses_state_json_and_names():
    state = json.dumps({"0xa4c1380000000001": {"state": "ON", "power": 64, "energy": 913.63, "linkquality": 126, "last_seen": "x"}})
    plan = importer.build_plan(configuration_yaml=Z2M_CONFIG, database_db=None, coordinator_backup=None, state_json=state)
    plug = next(d for d in plan.devices if d.ieee == 0xA4C1380000000001)
    assert plug.friendly_name == "Workshop - Smart Plug" and not plug.endpoints and plug.last_state["power"] == 64
    from oneroof_zigbee.devices import Registry
    import tempfile
    from pathlib import Path
    reg = Registry(Path(tempfile.mkdtemp()) / "d.json")
    importer.apply_plan(plan, reg, NetworkSecrets.generate(15))
    d = reg.get(0xA4C1380000000001)
    assert d.state["power"] == 64 and "last_seen" not in d.state and d.interviewed is False


async def test_imported_device_without_endpoints_gets_full_interview(ui, tmp_path):  # noqa: F811
    fake, gw, server, api = ui
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    api.admin = Admin(gw.cfg, None, PasswordFile(tmp_path / "p"), Acl(), gw.control_users)
    st, _, body = await http(server.port, "POST", "/api/import/apply", {"configuration.yaml": Z2M_CONFIG})  # no database.db
    assert st == 200
    dev = gw.registry.get(0xA4C1380000000001)
    assert dev and not dev.endpoints and not dev.interviewed and dev.nwk == 0
    fake.nwk_to_ieee[0x98C3] = 0xA4C1380000000001  # the network knows it; we don't yet
    fake.requests.clear()
    fake.emit_incoming(0x98C3, 0x0006, bytes([0x18, 0x01, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(0xA4C1380000000001).interviewed:
            break
    d = gw.registry.get(0xA4C1380000000001)
    assert d.nwk == 0x98C3, "short address learned via ZDO IEEE lookup"
    assert d.interviewed and d.endpoints[1].in_clusters == [0, 6, 8], "full interview ran on first contact"
    assert d.friendly_name == "Workshop - Smart Plug"
    # a genuinely unknown short address is still alerted - on its first frame, then the tenth,
    # hundredth and thousandth, not on every frame - and lookups are rate-limited
    alerts = []
    gw.audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    for seq in range(1, 11):
        fake.emit_incoming(0x7777, 0x0006, bytes([0x18, seq, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    await asyncio.sleep(0.3)
    assert [a["type"] for a in alerts].count("traffic_from_unknown_device") == 2, "frame 1 and frame 10"
    assert [a.get("frames") for a in alerts if a["type"] == "traffic_from_unknown_device"] == [1, 10]
    assert sum(1 for f in fake.requests if f.subsystem.name == "ZDO" and f.command == 0x01 and int.from_bytes(f.data[0:2], "little") == 0x7777) == 1


async def test_imported_devices_are_located_at_startup(ui, tmp_path):  # noqa: F811
    """Awake devices answer the start-up address lookup and get interviewed without sending anything first."""
    fake, gw, server, api = ui
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    api.admin = Admin(gw.cfg, None, PasswordFile(tmp_path / "p"), Acl(), gw.control_users)
    st, _, _ = await http(server.port, "POST", "/api/import/apply", {"configuration.yaml": Z2M_CONFIG})
    assert st == 200
    fake.nwk_to_ieee[0x98C3] = 0xA4C1380000000001  # mains plug: awake, answers NWK_ADDR_REQ
    pending = [d for d in gw.registry.all() if d.context.get("imported_from") and not d.context.get("reporting_done")]
    assert pending
    orig_sleep = asyncio.sleep
    task = asyncio.create_task(gw._locate_imported(pending))
    for _ in range(200):
        await orig_sleep(0.05)
        if gw.registry.get(0xA4C1380000000001).interviewed:
            break
    task.cancel()
    d = gw.registry.get(0xA4C1380000000001)
    assert d.nwk == 0x98C3 and d.interviewed and d.endpoints, "located by ZDO broadcast and interviewed"
    lookups = [f for f in fake.requests if f.subsystem.name == "ZDO" and f.command == 0x00]
    assert lookups, "NWK_ADDR_REQ was sent"
    # devices that stayed silent (sleepy) are untouched and still wait for their first frame
    others = [x for x in pending if x.ieee != 0xA4C1380000000001]
    assert all(not x.interviewed for x in others)


async def test_manual_interview_never_targets_address_zero(ui, tmp_path):  # noqa: F811
    """An imported device with an unknown short address is resolved first; address 0 is the coordinator."""
    fake, gw, server, api = ui
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    api.admin = Admin(gw.cfg, None, PasswordFile(tmp_path / "p"), Acl(), gw.control_users)
    st, _, _ = await http(server.port, "POST", "/api/import/apply", {"configuration.yaml": Z2M_CONFIG})
    assert st == 200
    ieee = 0xA4C1380000000001
    dev = gw.registry.get(ieee)
    assert dev.nwk == 0 and gw.registry.by_nwk(0) is None
    # nobody answers: the interview fails with a clear reason, no ZDO descriptor request goes to 0x0000
    fake.requests.clear()
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/interview", {})
    for _ in range(160):
        await asyncio.sleep(0.05)  # the lookup waits up to 6 s for an answer
        if gw.registry.get(ieee).interview_error:
            break
    assert "address lookup" in (gw.registry.get(ieee).interview_error or "")
    assert not [f for f in fake.requests if f.subsystem.name == "ZDO" and f.command in (0x02, 0x05) and f.data[:2] == b"\x00\x00"]
    assert not gw.registry.get(ieee).interviewed
    # once the network knows it, the same button works and learns the real address
    fake.nwk_to_ieee[0x98C3] = ieee
    st, _, _ = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/interview", {})
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(ieee).interviewed:
            break
    d = gw.registry.get(ieee)
    assert d.interviewed and d.nwk == 0x98C3 and d.endpoints[1].in_clusters == [0, 6, 8]


BACKUP_WITH_DEVICES = json.dumps({
    "metadata": {"format": "zigpy/open-coordinator-backup", "version": 1},
    "coordinator_ieee": "00124b0001020304", "pan_id": "1a62", "extended_pan_id": "a1b2c3d4e5f60718",
    "channel": 11, "network_key": {"key": "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "frame_counter": 1234567},
    "devices": [
        {"nwk_address": "98c3", "ieee_address": "a4c1380000000001", "is_child": False},
        {"nwk_address": "b821", "ieee_address": "00158d0000000099", "is_child": False},  # not in configuration.yaml
    ],
})


def test_backup_device_table_gives_short_addresses_and_ext_pan_order():
    plan = importer.build_plan(configuration_yaml=Z2M_CONFIG, database_db=None, coordinator_backup=BACKUP_WITH_DEVICES)
    plug = next(d for d in plan.devices if d.ieee == 0xA4C1380000000001)
    assert plug.nwk == 0x98C3, "address taken from the backup's device table"
    assert all(d.ieee != 0x00158D0000000099 for d in plan.devices), "devices the previous setup no longer lists are not resurrected"
    # the coordinator stores the extended PAN id least-significant byte first; the files list it the other way round
    assert plan.network.ext_pan_id.to_bytes(8, "little").hex() == "1807f6e5d4c3b2a1"
    cfg_only = importer.build_plan(configuration_yaml=Z2M_CONFIG.replace("[221, 221, 221, 221, 221, 221, 221, 221]",
                                                                         "[161, 178, 195, 212, 229, 246, 7, 24]"),
                                   database_db=None, coordinator_backup=None)
    assert cfg_only.network.ext_pan_id == plan.network.ext_pan_id, "configuration.yaml list and backup string agree"


async def test_imported_devices_with_known_addresses_are_interviewed_directly(ui, tmp_path):  # noqa: F811
    """Addresses from the backup's device table: no ZDO broadcast, the device is asked straight away."""
    fake, gw, server, api = ui
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    api.admin = Admin(gw.cfg, None, PasswordFile(tmp_path / "p"), Acl(), gw.control_users)
    st, _, _ = await http(server.port, "POST", "/api/import/apply", {"configuration.yaml": Z2M_CONFIG, "coordinator_backup.json": BACKUP_WITH_DEVICES})
    assert st == 200
    dev = gw.registry.get(0xA4C1380000000001)
    assert dev.nwk == 0x98C3 and not dev.interviewed
    fake.requests.clear()
    pending = [d for d in gw.registry.all() if d.context.get("imported_from") and not d.context.get("reporting_done")]
    task = asyncio.create_task(gw._locate_imported(pending))
    for _ in range(200):
        await asyncio.sleep(0.05)
        if gw.registry.get(0xA4C1380000000001).interviewed:
            break
    task.cancel()
    d = gw.registry.get(0xA4C1380000000001)
    assert d.interviewed and d.endpoints[1].in_clusters == [0, 6, 8]
    assert not [f for f in fake.requests if f.subsystem.name == "ZDO" and f.command == 0x00 and f.data[:8] == (0xA4C1380000000001).to_bytes(8, "little")], \
        "no NWK_ADDR_REQ for a device whose address is known"


def test_backup_trust_centre_seed_is_imported_into_the_secrets():
    raw = json.loads(BACKUP_WITH_DEVICES)
    raw["stack_specific"] = {"zstack": {"tclk_seed": "00112233445566778899aabbccddeeff"}}
    plan = importer.build_plan(configuration_yaml=Z2M_CONFIG, database_db=None, coordinator_backup=json.dumps(raw))
    assert plan.network.tclk_seed == bytes.fromhex("00112233445566778899aabbccddeeff")
    from oneroof_zigbee.devices import Registry
    import tempfile
    from pathlib import Path
    reg = Registry(Path(tempfile.mkdtemp()) / "d.json")
    secrets = importer.apply_plan(plan, reg, NetworkSecrets.generate(15))
    assert secrets.tclk_seed == plan.network.tclk_seed
    assert NetworkSecrets.from_json(secrets.to_json()).tclk_seed == secrets.tclk_seed, "survives the keystore round trip"
