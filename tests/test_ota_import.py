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
    assert s["network"]["key_is_z2m_default"] is True
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
    assert d.friendly_name == "Workshop - Smart Plug" and d.interviewed and d.context["imported_from"] == "zigbee2mqtt"
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
