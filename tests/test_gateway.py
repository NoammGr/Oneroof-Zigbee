import asyncio
import json

from oneroof_zigbee.config import Config
from oneroof_zigbee.devices import Registry
from oneroof_zigbee.gateway import Gateway
from oneroof_zigbee.mqtt.packets import topic_matches
from oneroof_zigbee.security import Audit, JoinGuard, JoinPolicy, NetworkSecrets
from oneroof_zigbee.znp import Coordinator, Transport
from oneroof_zigbee.znp import commands as c
from oneroof_zigbee.znp.unpi import Frame, FrameType, Subsystem
from oneroof_zigbee.znp.wire import Writer
from tests.fake_znp import FakeZnp

IEEE = 0x00124B00DEADBEEF
NWK = 0x5678


class FakeBroker:
    """In-process stand-in with the same publish/subscribe surface."""

    def __init__(self) -> None:
        self.published: list[tuple[str, bytes, bool]] = []
        self.subs: list[tuple[str, object]] = []

    async def publish(self, topic, payload, retain=False, qos=0):
        self.published.append((topic, payload, retain))

    def subscribe(self, topic_filter, cb):
        self.subs.append((topic_filter, cb))
        return lambda: None

    async def inject(self, topic, payload, user="homeassistant"):
        for f, cb in self.subs:
            if topic_matches(f, topic):
                await cb(topic, payload, user)

    def last(self, topic):
        for t, p, _ in reversed(self.published):
            if t == topic:
                return p
        return None


def _zcl_read_rsp(seq, records):
    """Build a ReadAttributesResponse ZCL frame: global, server→client."""
    body = b""
    for attr, dtype, raw in records:
        body += attr.to_bytes(2, "little") + b"\x00" + bytes([dtype]) + raw
    return bytes([0x18, seq, 0x01]) + body


def _fake_device_responses(fake: FakeZnp):
    """Answer ZCL reads coming from the gateway on cluster 0 / 6 / 8 and ack reporting config."""

    def hook(f: Frame):
        dst = int.from_bytes(f.data[0:2], "little")
        src_ep = f.data[3]
        dst_ep = f.data[2]
        cluster = int.from_bytes(f.data[4:6], "little")
        zcl = f.data[10:]
        seq = zcl[1] if not (zcl[0] & 0x04) else zcl[3]
        cmd = zcl[2] if not (zcl[0] & 0x04) else zcl[4]
        out = []

        def reply(payload):
            w = Writer().u16(0).u16(cluster).u16(dst).u8(dst_ep).u8(src_ep).u8(0).u8(180).u8(1).u32(0).u8(seq).lv(payload)
            out.append(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))

        if cmd == 0x00 and cluster == 0x0000:  # read basic
            reply(_zcl_read_rsp(seq, [(0x0004, 0x42, b"\x05Acme!"), (0x0005, 0x42, b"\x06Bulb-1"), (0x0007, 0x30, b"\x01")]))
        elif cmd == 0x00 and cluster == 0x0006:
            reply(_zcl_read_rsp(seq, [(0x0000, 0x10, b"\x01")]))
        elif cmd == 0x00 and cluster == 0x0008:
            reply(_zcl_read_rsp(seq, [(0x0000, 0x20, b"\x7f")]))
        elif cmd == 0x06:  # configure reporting → rsp success
            reply(bytes([0x18, seq, 0x07, 0x00]))
        elif cmd == 0x02:  # write attributes → rsp success
            reply(bytes([0x18, seq, 0x04, 0x00]))
        return out

    fake.on_data_request = hook


async def make(tmp_path):
    fake = FakeZnp()
    _fake_device_responses(fake)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    guard = JoinGuard(JoinPolicy(cooldown_seconds=0), Audit(None))
    coord = Coordinator(t, NetworkSecrets.generate(15), guard, guard.audit)
    await asyncio.wait_for(coord.start(), 5)
    cfg = Config.from_dict({"serial": {"port": "/dev/null"}, "data_dir": str(tmp_path)})
    broker = FakeBroker()
    gw = Gateway(cfg, coord, broker, guard.audit, Registry(tmp_path / "devices.json"), control_users={"admin"})
    await gw.start()
    return fake, coord, broker, gw, t


async def test_join_interview_discovery_and_state(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    assert broker.last("oneroof/zigbee/bridge/state") == b"online"

    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="admin")
    rsp = json.loads(broker.last("oneroof/zigbee/bridge/response/permit_join"))
    assert rsp["ok"] and rsp["seconds"] == 30

    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    dev = gw.registry.get(IEEE)
    assert dev and dev.interviewed
    assert dev.manufacturer == "Acme!" and dev.model == "Bulb-1"
    assert dev.endpoints[1].in_clusters == [0, 6, 8] and dev.endpoints[1].category == "light"

    # discovery published for a dimmable light
    cfg_topic = f"homeassistant/light/{dev.ieee_str}/light/config"
    disc = json.loads(broker.last(cfg_topic))
    assert disc["schema"] == "json" and disc["brightness"] is True and disc["command_topic"] == f"oneroof/zigbee/{dev.ieee_str}/set"
    assert disc["unique_id"] == f"oneroof_zigbee_{dev.ieee_str}_light"

    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["state"] == "ON" and state["brightness"] == 127

    # bind + configure reporting happened for on/off and level
    binds = [f for f in fake.requests if f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.BIND_REQ]
    assert {int.from_bytes(f.data[11:13], "little") for f in binds} >= {0x0006, 0x0008}
    await t.close()


async def test_set_command_sends_zcl_and_updates_state(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="admin")
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    dev = gw.registry.get(IEEE)
    fake.requests.clear()

    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"state": "ON", "brightness": 200, "transition": 1.5}')
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1
    cluster = int.from_bytes(reqs[0].data[4:6], "little")
    zcl = reqs[0].data[10:]
    assert cluster == 0x0008 and zcl[2] == 0x04  # move_to_level_with_on_off
    assert zcl[3] == 200 and int.from_bytes(zcl[4:6], "little") == 15
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["brightness"] == 200 and state["state"] == "ON"

    # attribute report from device updates state
    fake.emit_incoming(NWK, 0x0006, bytes([0x18, 0x33, 0x0A, 0x00, 0x00, 0x10, 0x00]))
    await asyncio.sleep(0.05)
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["state"] == "OFF"
    await t.close()


async def test_permit_join_requires_control_user(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    alerts = []
    coord.audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="homeassistant")
    rsp = json.loads(broker.last("oneroof/zigbee/bridge/response/permit_join"))
    assert rsp == {"ok": False, "error": "not authorized"}
    assert any(a["type"] == "request_denied" for a in alerts)
    assert coord.guard.window is None
    # security alert is published retained
    await asyncio.sleep(0)
    sec = json.loads(broker.last("oneroof/zigbee/bridge/security"))
    assert sec["type"] == "request_denied"
    await t.close()


async def test_unknown_device_traffic_alerts(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    fake.emit_incoming(0x9999, 0x0006, bytes([0x18, 0x01, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    await asyncio.sleep(0.05)
    sec = json.loads(broker.last("oneroof/zigbee/bridge/security"))
    assert sec["type"] == "traffic_from_unknown_device" and sec["nwk"] == "0x9999"
    await t.close()


async def test_remove_device_clears_discovery(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="admin")
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    dev = gw.registry.get(IEEE)
    await broker.inject("oneroof/zigbee/bridge/request/remove", json.dumps({"ieee": dev.ieee_str}).encode(), user="admin")
    assert json.loads(broker.last("oneroof/zigbee/bridge/response/remove"))["ok"]
    assert gw.registry.get(IEEE) is None
    assert broker.last(f"homeassistant/light/{dev.ieee_str}/light/config") == b""
    assert broker.last(f"oneroof/zigbee/{dev.ieee_str}/state") == b""
    await t.close()


async def test_over_the_air_key_rotation_keeps_devices_and_locks_out_old_key(tmp_path):
    """Rotate without re-pairing: every device gets the new key under its own link key, then a
    switch is broadcast; the radio and the keystore end up on the new key, registry untouched."""
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)  # as the runtime would have
    gw.registry.add_or_update(0x00158D0000000001, 0x1234, is_router=True)
    gw.registry.add_or_update(0x00158D0000000002, 0x5678, is_router=False)
    gw.registry.add_or_update(0x00158D0000000003, 0, is_router=False)  # address unknown: skipped, reported
    old_key = coord.secrets.network_key
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    from oneroof_zigbee.rotation import KeyRotation
    KeyRotation.MIN_WINDOW_S = 1
    result = await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    assert result["ok"] and result["rotation"]["phase"] in ("delivering", "waiting")
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] == "waiting":
            break
    st = gw.rotation_status()
    assert sorted(st["delivered"]) == ["0x00158d0000000001", "0x00158d0000000002"]
    assert st["failed"] == {"0x00158d0000000003": "address unknown"}
    assert sorted(d for d, _ in fake.key_deliveries) == [0x1234, 0x5678], "unicast to each device, never to 0x0000/broadcast"
    assert fake.active_key == old_key, "nothing switches before the delivery window ends"
    for _ in range(150):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "failed"):
            break
    st = gw.rotation_status()
    assert st["phase"] == "done", st
    new = Keystore(tmp_path / "network.keystore").load()
    assert new.network_key != old_key and fake.active_key == new.network_key and coord.secrets.network_key == new.network_key
    assert new.pan_id == coord.secrets.pan_id and new.tclk_seed == coord.secrets.tclk_seed
    assert len(gw.registry.all()) == 3, "no device removed"
    types = [e["type"] for e in events]
    assert "network_key_rotation_started" in types and "network_key_rotated" in types
    assert [e for e in events if e["type"] == "network_key_rotated"][-1]["verified"] is True
    # control-user gate still applies
    denied = await gw.handle_request("rotate_network_key", {}, "homeassistant")
    assert denied == {"ok": False, "error": "not authorized"}
    await t.close()


async def test_plain_join_closes_the_window_and_rotates_the_key(tmp_path):
    """A window without install code admits one device, closes at once, and — once the device has
    its own link key (interview done) — the network key is rotated over the air."""
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    KeyRotation.MIN_WINDOW_S = 1
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    old_key = coord.secrets.network_key
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
    assert coord.guard.window is not None and coord.guard.window.install_code is False
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    assert coord.guard.window is None, "window closed right after the first join"
    assert fake.permit_durations[-1] == 0
    assert "permit_join_closed_after_join" in [e["type"] for e in events]
    # a second device announcing now is unexpected and evicted
    fake.emit_announce(IEEE + 1, NWK + 1)
    await asyncio.sleep(0.1)
    assert any(e["type"] == "unexpected_join" for e in events)
    # rotation was started by policy and completes
    assert any(e["type"] == "key_rotation_after_plain_join" for e in events)
    gw._rotation.state.window_s = 1
    for _ in range(200):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "failed"):
            break
    assert gw.rotation_status()["phase"] == "done"
    assert Keystore(tmp_path / "network.keystore").load().network_key != old_key
    assert fake.active_key == coord.secrets.network_key
    await t.close()


async def test_install_code_join_does_not_rotate(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    code = "83FED3407A939723A5C639B26916D505C3B5"
    await broker.inject("oneroof/zigbee/bridge/request/permit_join",
                        json.dumps({"seconds": 60, "ieee": f"0x{IEEE:016x}", "install_code": code}).encode(), user="admin")
    assert coord.guard.window is not None and coord.guard.window.install_code is True
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    await asyncio.sleep(0.05)
    types = [e["type"] for e in events]
    assert "permit_join_closed_after_join" in types and "key_rotation_after_plain_join" not in types
    await t.close()


async def test_silent_routers_are_polled_and_lqi_seeded_from_state(tmp_path):
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0x00158D0000000011, NWK, is_router=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0, 6, 8], [], "light")
    dev.interviewed = True
    dev.state["linkquality"] = 77
    dev.last_seen = 0.0
    dev.lqi = None
    # seeding happens at start: emulate the start-up pass
    for d in gw.registry.all():
        if d.lqi is None and isinstance(d.state.get("linkquality"), int):
            d.lqi = d.state["linkquality"]
    assert dev.lqi == 77
    fake.requests.clear()
    await gw._poll_silent_routers()
    reads = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == 0x01 and int.from_bytes(f.data[4:6], "little") == 0x0006]
    assert reads, "on/off attribute read sent to the silent router"
    assert dev.state.get("state") == "ON" and dev.last_seen > 0, "answer applied; last-seen refreshed"
    await t.close()


async def test_identity_and_vendor_heartbeat_attributes_never_become_state(tmp_path):
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0xA4C1380000000077, 0x4321, is_router=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0, 6], [], "plug")
    dev.interviewed = True
    before = len(gw.activity)
    events = gw._apply_changes(dev, {"app_version": 80, "basic_0xffe2": 56, "basic_0xffe4": 0, "state": "ON"})
    assert "app_version" not in dev.state and "basic_0xffe2" not in dev.state and dev.state["state"] == "ON"
    assert dev.app_version == 80 and dev.context["basic_extra"] == {"basic_0xffe2": 56, "basic_0xffe4": 0}
    assert all(e["key"] == "state" for e in events) and all(r["key"] == "state" for r in list(gw.activity)[before:])
    assert gw._apply_changes(dev, {"basic_0xffe2": 57}) == []
    await t.close()
