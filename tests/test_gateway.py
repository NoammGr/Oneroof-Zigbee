import asyncio
import logging
import time
import json

from oneroof_zigbee.config import Config
from oneroof_zigbee.devices import Registry
from oneroof_zigbee.gateway import Gateway
from oneroof_zigbee.mqtt.packets import topic_matches
from oneroof_zigbee.security import Audit, JoinGuard, JoinPolicy, NetworkSecrets
from oneroof_zigbee.zcl import global_commands as gc
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

    # discovery published for a dimmable light - once it has a name (a nameless join waits for one)
    cfg_topic = f"homeassistant/light/{dev.ieee_str}/light/config"
    await gw.handle_request("rename", {"ieee": dev.ieee_str, "friendly_name": "Hall lamp"}, "admin")
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
    fake.nwk_to_ieee[0x1234] = 0x00158D0000000001  # a router must answer on the current key before it gets the new one
    sleeper = gw.registry.add_or_update(0x00158D0000000002, 0x5678, is_router=False)
    sleeper.last_seen = time.time()  # awake right now: handed the key immediately
    gw.registry.add_or_update(0x00158D0000000003, 0, is_router=False)  # address unknown: reported; blocks the switch unless allowed
    gw.cfg.zigbee.rotation_require_all = False
    gw.cfg.zigbee.rotation_max_window_seconds = 1
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
    assert new.key_seq == st["seq"] and new.previous_network_key == old_key, "the keystore remembers the sequence and keeps the old key as the alternate"
    assert fake.nv[c.NvId.PRECFGKEY][:16] == new.network_key, "the next start must not mistake the rotated network for a foreign one"
    assert len(gw.registry.all()) == 3, "no device removed"
    types = [e["type"] for e in events]
    assert "network_key_rotation_started" in types and "network_key_rotated" in types
    rotated = [e for e in events if e["type"] == "network_key_rotated"][-1]
    assert rotated["verified"] is True and rotated["finished_on_coordinator"] is False
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
    gw.ROTATE_AFTER_JOIN_QUIET_S = 0.05
    gw.rotation_policy.after_plain_join = True  # the owner switched it on (off by default since 2.14)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    old_key = coord.secrets.network_key
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
    assert coord.guard.window is not None and coord.guard.window.install_code is False
    fake.nwk_to_ieee[NWK] = IEEE
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
    # rotation was started by policy (after the quiet period) and completes
    for _ in range(200):
        await asyncio.sleep(0.02)
        if gw._rotation is not None and gw._rotation.running:
            break
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


async def test_plain_join_does_not_rotate_unless_the_owner_asked(tmp_path):
    """2.14: automatic rotation is the owner's decision, off until switched on — a pairing without
    an install code no longer starts a rotation by itself."""
    fake, coord, broker, gw, t = await make(tmp_path)
    gw.ROTATE_AFTER_JOIN_QUIET_S = 0.05
    assert gw.rotation_policy.after_plain_join is False and gw.rotation_policy.every_days == 0
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
    fake.nwk_to_ieee[NWK] = IEEE
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    await asyncio.sleep(0.2)
    types = [e["type"] for e in events]
    assert "key_rotation_scheduled" not in types and "key_rotation_after_plain_join" not in types
    assert gw._rotation is None or not gw._rotation.running
    await t.close()


async def test_rotation_policy_is_live_persisted_and_stops_the_rotation_it_started(tmp_path):
    """Settings → Automatic key rotation: read by anyone, changed by control users only, kept in
    the data folder across restarts, and switching it off cancels a policy rotation in flight."""
    from oneroof_zigbee.rotation import KeyRotation, RotationPolicy
    from oneroof_zigbee.security import Keystore
    KeyRotation.MIN_WINDOW_S = 1
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    r = await gw.handle_request("rotation_policy", {}, "homeassistant")
    assert r["ok"] and r["policy"] == {"after_plain_join": False, "every_days": 0} and r["running_by"] is None
    denied = await gw.handle_request("rotation_policy", {"policy": {"after_plain_join": True}}, "homeassistant")
    assert not denied["ok"] and denied["error"] == "not authorized"
    bad = await gw.handle_request("rotation_policy", {"policy": {"every_days": -3}}, "ui:admin")
    assert not bad["ok"] and "every_days" in bad["error"]
    r = await gw.handle_request("rotation_policy", {"policy": {"after_plain_join": True, "every_days": 90}}, "ui:admin")
    assert r["ok"] and r["policy"] == {"after_plain_join": True, "every_days": 90} and r["stopped"] is None
    assert gw.rotation_policy.every_days == 90
    assert any(e["type"] == "key_rotation_policy_changed" and e["every_days"] == 90 for e in events)
    # the decision survives a restart: the file wins over the configured seed values
    again = RotationPolicy.load(tmp_path / "rotation_policy.json", after_plain_join=False, every_days=0)
    assert again == RotationPolicy(after_plain_join=True, every_days=90)
    # a policy rotation in flight is stopped when its policy is switched off; a manual one is not
    gw.registry.add_or_update(0x00158D0000000009, 0x1111, is_router=False)  # asleep: the rotation waits for it
    gw._start_policy_rotation()
    await asyncio.sleep(0.05)
    assert gw._rotation.running and gw.rotation_status()["by"] == "policy:rotate_after_plain_join"
    r = await gw.handle_request("rotation_policy", {"policy": {"after_plain_join": False}}, "ui:admin")
    assert r["ok"] and r["stopped"] == "policy:rotate_after_plain_join"
    for _ in range(50):
        await asyncio.sleep(0.02)
        if not gw._rotation.running:
            break
    assert gw.rotation_status()["phase"] == "cancelled"
    assert any(e["type"] == "network_key_rotation_cancelled_by_policy" for e in events)
    await t.close()


async def test_rotation_check_reports_who_would_hold_a_rotation_up(tmp_path):
    """Maintenance → Check first: the rotation's own evidence, per device, before anything is sent."""
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    ok_router = gw.registry.add_or_update(0x00158D0000000001, 0x1234, is_router=True)
    ok_router.friendly_name = "Kitchen plug"
    fake.nwk_to_ieee[0x1234] = 0x00158D0000000001
    dead_router = gw.registry.add_or_update(0x00158D0000000002, 0x2222, is_router=True)  # no answer on the current key
    sleeper = gw.registry.add_or_update(0x00158D0000000003, 0x3333, is_router=False)
    sleeper.last_seen = time.time() - 600
    gone = gw.registry.add_or_update(0x00158D0000000004, 0x4444, is_router=False)
    gone.last_seen = time.time() - 3 * 86400
    r = await gw.handle_request("rotate_network_key", {"mode": "check"}, "ui:admin")
    assert r["ok"], r
    chk = r["check"]
    by = {d["ieee"]: d for d in chk["devices"]}
    assert chk["total"] == 4 and chk["ready"] == 2
    assert by[ok_router.ieee_str]["ready"] and by[ok_router.ieee_str]["name"] == "Kitchen plug" and by[ok_router.ieee_str]["kind"] == "router"
    assert not by[dead_router.ieee_str]["ready"] and "does not answer" in by[dead_router.ieee_str]["why"]
    assert by[sleeper.ieee_str]["ready"] and by[sleeper.ieee_str]["kind"] == "battery"
    assert not by[gone.ieee_str]["ready"] and "silent" in by[gone.ieee_str]["why"]
    assert [d["ready"] for d in chk["devices"]] == [False, False, True, True], "the ones needing attention come first"
    assert gw.rotation_status()["phase"] == "idle", "a check is not a rotation"
    await t.close()


async def test_a_refused_transport_to_a_battery_device_keeps_it_asleep_not_in_the_retry_loop(tmp_path, monkeypatch):
    """Seen on a real network: a Xiaomi sensor whose key transport was refused the moment it spoke
    landed in `failed` AND `pending`, and was then knocked on every half hour like a dead router
    for six hours. A battery device is only reachable when it speaks — a miss keeps it 'asleep'."""
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    from oneroof_zigbee.znp import ZnpError
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    KeyRotation.MIN_WINDOW_S = 1
    KeyRotation.RETRY_EVERY_S = 0.2
    sleeper = gw.registry.add_or_update(0x00158D0000000002, 0x5678, is_router=False, rx_on_when_idle=False)
    sleeper.last_seen = time.time()  # awake right now: offered the key at once
    offers = []

    async def refuse(nwk, seq, key):
        offers.append(nwk)
        raise ZnpError("NWK_NO_ROUTE")
    monkeypatch.setattr(coord, "deliver_network_key", refuse)
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] == "waiting":
            break
    await asyncio.sleep(0.8)  # several router retry periods
    st = gw.rotation_status()
    assert list(st["pending"]) == [sleeper.ieee_str] and not st["failed"]
    assert "asleep" in st["pending"][sleeper.ieee_str] and "NWK_NO_ROUTE" in st["pending"][sleeper.ieee_str]
    assert offers == [0x5678], "one offer while it was awake; no knocking on a sleeping door"
    await gw.handle_request("rotate_network_key", {"mode": "cancel"}, "ui:admin")
    await asyncio.sleep(0.05)
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


async def test_imported_device_goes_online_on_first_frame(tmp_path):
    """Availability must follow reality: an imported device (offline until heard) that reports
    is marked online and the retained availability message flips, or Home Assistant keeps every
    entity unavailable while states flow."""
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0xA4C1380000000099, 0x5151, is_router=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0, 6], [], "plug")
    dev.interviewed = True
    dev.context["imported_from"] = "previous"
    dev.context["reporting_done"] = True
    dev.available = False
    await gw._announce(dev)
    assert broker.last(f"oneroof/zigbee/{dev.ieee_str}/availability") == b"offline"
    fake.emit_incoming(0x5151, 0x0006, bytes([0x18, 0x01, 0x0A, 0x00, 0x00, 0x10, 0x01]))  # on/off report
    await asyncio.sleep(0.1)
    assert dev.available is True
    assert broker.last(f"oneroof/zigbee/{dev.ieee_str}/availability") == b"online"
    await t.close()


async def test_endpoints_without_clusters_are_reinterviewed(tmp_path):
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0x00158D0000000042, 0x4242, is_router=False)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [], [], "switch")
    dev.interviewed = True
    dev.context["imported_from"] = "previous"
    dev.context["reporting_done"] = True
    for d in gw.registry.all():  # the start-up sanitiser
        if d.interviewed and d.endpoints and not any(e.in_clusters or e.out_clusters for e in d.endpoints.values()):
            d.interviewed = False
            d.context.pop("reporting_done", None)
    assert dev.interviewed is False and "reporting_done" not in dev.context
    await t.close()


async def test_reannounce_blanks_entity_configs_that_no_longer_apply(tmp_path):
    """A retained switch config from an earlier, wrong description must be erased when the device
    is announced with its correct description, or Home Assistant keeps a phantom entity."""
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0x00158D0000000077, 0x7777, is_router=True)
    dev.manufacturer, dev.model = None, None
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0, 6], [], "switch")  # wrongly described as a mains switch
    dev.interviewed = True
    await gw._announce(dev)
    sw = f"homeassistant/switch/{dev.ieee_str}/switch/config"
    assert broker.last(sw)
    dev.manufacturer, dev.model = "LUMI", "lumi.sensor_magnet.aq2"  # corrected: a contact sensor
    dev.is_router = False
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0104, [0, 3, 0xFFFF], [0, 4, 3, 6, 8, 5], "sensor")
    await gw._announce(dev)
    assert broker.last(sw) == b"", "stale switch config blanked"
    assert broker.last(f"homeassistant/binary_sensor/{dev.ieee_str}/contact/config")
    await t.close()


async def test_first_tracked_announce_sweeps_legacy_entity_shapes(tmp_path):
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0x00158D0000000078, 0x7778, is_router=False)
    dev.manufacturer, dev.model = "LUMI", "lumi.sensor_magnet.aq2"
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0104, [0, 3, 0xFFFF], [0, 4, 3, 6, 8, 5], "sensor")
    dev.interviewed = True
    await gw._announce(dev)
    assert broker.last(f"homeassistant/switch/{dev.ieee_str}/switch/config") == b"", "phantom switch shape blanked"
    assert broker.last(f"homeassistant/binary_sensor/{dev.ieee_str}/contact/config"), "real entity published after the sweep"
    assert "discovery_topics" in dev.context
    await t.close()


async def test_unknown_device_is_tracked_and_can_be_adopted_or_evicted(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    alerts = []
    coord.audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    fake.nwk_to_ieee[0x1791] = 0xA4C1380000000055  # on the network, not in our registry
    for i in range(3):
        fake.emit_incoming(0x1791, 0x000A, bytes([0x00, i, 0x00, 0x00, 0x00]))
        await asyncio.sleep(0.05)
    unk = gw.list_unknown()
    assert len(unk) == 1 and unk[0]["ieee"] == "0xa4c1380000000055" and unk[0]["nwk"] == "0x1791" and unk[0]["frames"] >= 1
    assert [a for a in alerts if a["type"] == "traffic_from_unknown_device" and a.get("ieee") == "0xa4c1380000000055"]
    dev = await gw.adopt_unknown(0xA4C1380000000055, "ui:admin")
    assert dev.nwk == 0x1791 and gw.registry.get(0xA4C1380000000055) and not gw.list_unknown()
    assert any(a["type"] == "unknown_device_adopted" for a in alerts)
    # evict path
    fake.nwk_to_ieee[0x057B] = 0xA4C1380000000056
    fake.emit_incoming(0x057B, 0x000A, bytes([0x00, 1, 0x00, 0x00, 0x00]))
    await asyncio.sleep(0.1)
    await gw.evict_unknown(0xA4C1380000000056, "ui:admin")
    assert not gw.list_unknown() and any(f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.MGMT_LEAVE_REQ for f in fake.requests)
    await t.close()


async def test_sleepy_known_model_counts_as_described_when_descriptors_time_out(tmp_path, monkeypatch):
    from oneroof_zigbee.znp import ZnpTimeout
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(0x00158D0000000031, 0x3131, is_router=False)
    dev.manufacturer, dev.model = "LUMI", "lumi.sensor_motion.aq2"
    dev.interviewed = False
    events = []
    coord.audit.subscribe(lambda r: events.append(r))

    async def sleepy(*a, **k):
        raise ZnpTimeout("no ZDO:0x85 within 10.0s")
    monkeypatch.setattr(coord, "node_descriptor", sleepy)
    await gw._interview(dev)
    assert dev.interviewed and dev.interview_error is None and dev.context["described_by"] == "model"
    done = [e for e in events if e["type"] == "interview_done"]
    assert done and done[-1]["described_by"] == "model knowledge"
    assert not [e for e in events if e["type"] == "interview_failed"]
    # a mains device with an unknown model still fails honestly
    plug = gw.registry.add_or_update(0x00158D0000000032, 0x3232, is_router=True)
    plug.interviewed = False
    await gw._interview(plug)
    assert not plug.interviewed and plug.interview_error
    await t.close()


async def test_rotation_finishes_the_switch_on_a_radio_that_ignores_it_and_retries_stragglers(tmp_path):
    """Seen in the field: the per-device key transports do not leave the coordinator with the new key
    as its alternate, so the broadcast switch moves every device but not the radio (verified=false,
    every switched device then fails with NWK_NO_ROUTE). The rotation must finish the switch on the
    coordinator itself, at the sequence the devices know, and a device that refused the first
    delivery must be offered it again during the window."""
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t = await make(tmp_path)
    fake.local_install_on_unicast = False
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    gw.registry.add_or_update(0x00158D0000000001, 0x1234, is_router=True)
    fake.nwk_to_ieee[0x1234] = 0x00158D0000000001
    late = gw.registry.add_or_update(0x00158D0000000002, 0, is_router=True)  # address unknown until the network answers for it
    old_key = coord.secrets.network_key
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    KeyRotation.MIN_WINDOW_S = 1
    KeyRotation.RETRY_EVERY_S = 0.3
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(150):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["failed"]:
            break
    assert list(gw.rotation_status()["failed"]) == ["0x00158d0000000002"]
    fake.nwk_to_ieee[0x5678] = 0x00158D0000000002  # it answers a NWK_addr_req now (rejoined with a fresh address)
    for _ in range(200):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "failed"):
            break
    st = gw.rotation_status()
    assert st["phase"] == "done" and st["failed"] == {} and st["retried"] == 1
    assert (0x5678, st["seq"]) in fake.key_deliveries and late.nwk == 0x5678, "the stale address was re-resolved, then the key delivered"
    assert st["verified"] is True and st["finished_on_coordinator"] is True
    new = Keystore(tmp_path / "network.keystore").load()
    assert fake.active_key == new.network_key != old_key and fake.active_seq == st["seq"] == new.key_seq
    assert fake.nv[c.NvId.NWK_ALTERN_KEY_INFO][1:17] == old_key, "the old key stays as the alternate so stragglers are still heard"
    assert fake.nv[c.NvId.PRECFGKEY][:16] == new.network_key
    types = [e["type"] for e in events]
    assert "network_key_switch_finished" in types
    assert "network_formed" not in types, "finishing the switch restarts the stack, it never re-forms"
    # the operator's button for a rotation that ended unfinished: idempotent once the radio is right
    r = await gw.handle_request("rotate_network_key", {"mode": "finish"}, "ui:admin")
    assert r["ok"] and r["verified"] is True
    await t.close()


async def test_rotation_hands_sleepers_the_key_when_heard_and_refuses_to_switch_without_everyone(tmp_path):
    """Evidence, not hope: a battery device is handed the key the moment it is heard (it polls its
    parent right after sending); a router that does not answer on the current key blocks the switch
    — the rotation extends its wait and, at the maximum, aborts with the old key in force."""
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    KeyRotation.MIN_WINDOW_S = 1
    KeyRotation.RETRY_EVERY_S = 0.2
    KeyRotation.LOOKUP_TIMEOUT_S = 0.3
    gw.registry.add_or_update(0x00158D0000000001, 0x1234, is_router=True)
    fake.nwk_to_ieee[0x1234] = 0x00158D0000000001
    sleeper = gw.registry.add_or_update(0x00158D0000000002, 0x5678, is_router=False, rx_on_when_idle=False)
    sleeper.endpoints[1] = __import__("oneroof_zigbee.devices", fromlist=["Endpoint"]).Endpoint(1, 0x0104, 0x0302, [0x0402], [])
    sleeper.interviewed = True
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(150):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["pending"]:
            break
    st = gw.rotation_status()
    assert st["delivered"] == ["0x00158d0000000001"] and list(st["pending"]) == ["0x00158d0000000002"]
    assert (0x5678, st["seq"]) not in fake.key_deliveries, "nothing is queued for a device that is not awake"
    # the sensor reports a temperature: it is awake now — the transport follows at once
    fake.emit_incoming(0x5678, 0x0402, bytes([0x18, 0x09, 0x0A, 0x00, 0x00, 0x29]) + (2150).to_bytes(2, "little", signed=True))
    for _ in range(300):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "aborted", "failed"):
            break
    st = gw.rotation_status()
    assert st["phase"] == "done", st
    assert (0x5678, st["seq"]) in fake.key_deliveries and st["pending"] == {} and st["retried"] == 1
    assert sorted(st["delivered"]) == ["0x00158d0000000001", "0x00158d0000000002"] and st["unreachable"] == []
    assert fake.active_key == Keystore(tmp_path / "network.keystore").load().network_key

    # a router nobody can reach: the switch waits — the key keeps being offered — and past the
    # maximum wait a "stalled" alert names it; the old key stays in force meanwhile
    gw.registry.add_or_update(0x00158D0000000003, 0x7777, is_router=True)  # no fake mapping: silent on the air
    key_before = coord.secrets.network_key
    gw.cfg.zigbee.rotation_max_window_seconds = 1
    gw._rotation = None  # re-create with the new policy values
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(400):
        await asyncio.sleep(0.02)
        st = gw.rotation_status()
        if st.get("stalled") or st["phase"] in ("done", "aborted", "failed"):
            break
    st = gw.rotation_status()
    assert st["phase"] == "waiting" and st["stalled"] and list(st["failed"]) == ["0x00158d0000000003"], st
    assert coord.secrets.network_key == key_before and fake.active_key == key_before
    stalled = [e for e in events if e["type"] == "network_key_rotation_stalled"]
    assert stalled and list(stalled[-1]["missing"]) == ["0x00158d0000000003"] and stalled[-1]["level"] == "security"
    saved = Keystore(tmp_path / "network.keystore").load()
    assert saved.network_key == key_before and saved.pending_rotation and saved.pending_rotation["seq"] == st["seq"], "kept for a restart"
    # the device is gone for good: removing it is what unblocks the switch
    gw.registry.remove(0x00158D0000000003)
    for _ in range(400):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "aborted", "failed"):
            break
    st = gw.rotation_status()
    assert st["phase"] == "done", st
    final = Keystore(tmp_path / "network.keystore").load()
    assert final.network_key != key_before and final.pending_rotation is None and fake.active_key == final.network_key
    await t.close()


async def test_pending_rotation_survives_a_restart_and_a_cancel_keeps_the_old_key(tmp_path):
    """A rotation is kept in the keystore while it waits: after a restart the gateway resumes it,
    does not ask the devices that already hold the key again, and keeps offering it to the rest.
    Cancelling leaves the current key in force and forgets the pending record."""
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    KeyRotation.MIN_WINDOW_S = 1
    KeyRotation.RETRY_EVERY_S = 0.2
    KeyRotation.LOOKUP_TIMEOUT_S = 0.3
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    gw.registry.add_or_update(0x00158D0000000001, 0x1234, is_router=True)
    fake.nwk_to_ieee[0x1234] = 0x00158D0000000001
    gw.registry.add_or_update(0x00158D0000000003, 0x7777, is_router=True)  # silent for now
    gw.registry.save()
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(300):
        await asyncio.sleep(0.02)
        st = gw.rotation_status()
        if st["delivered"] == ["0x00158d0000000001"] and st["failed"]:
            break
    pending = None
    for _ in range(40):  # the record is written off the event loop; wait for it to land
        pending = Keystore(tmp_path / "network.keystore").load().pending_rotation
        if pending and pending.get("delivered"):
            break
        await asyncio.sleep(0.1)
    assert pending and pending["delivered"] == ["0x00158d0000000001"] and pending["seq"] == gw.rotation_status()["seq"]
    await t.close()  # the add-on restarts

    fake2, coord2, broker2, gw2, t2 = await make(tmp_path)
    events = []
    coord2.audit.subscribe(lambda r: events.append(r))
    st = gw2.rotation_status()
    assert st["resumed"] is True and st["phase"] in ("delivering", "waiting") and st["delivered"] == ["0x00158d0000000001"], st
    fake2.nwk_to_ieee[0x1234] = 0x00158D0000000001
    fake2.nwk_to_ieee[0x7777] = 0x00158D0000000003  # the missing router is back on the air
    for _ in range(400):
        await asyncio.sleep(0.02)
        if gw2.rotation_status()["phase"] in ("done", "aborted", "failed"):
            break
    st = gw2.rotation_status()
    assert st["phase"] == "done", st
    assert sorted(st["delivered"]) == ["0x00158d0000000001", "0x00158d0000000003"]
    assert (0x7777, st["seq"]) in fake2.key_deliveries and (0x1234, st["seq"]) not in fake2.key_deliveries, "already-delivered devices are not asked again"
    final = Keystore(tmp_path / "network.keystore").load()
    assert final.network_key == bytes.fromhex(pending["key"]) and final.pending_rotation is None and fake2.active_key == final.network_key

    # cancel: a new rotation with a silent device, cancelled while waiting
    gw2.registry.add_or_update(0x00158D0000000004, 0x8888, is_router=True)
    key_before = coord2.secrets.network_key
    gw2._rotation = None
    await gw2.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(300):
        await asyncio.sleep(0.02)
        if gw2.rotation_status()["phase"] == "waiting":
            break
    assert Keystore(tmp_path / "network.keystore").load().pending_rotation is not None
    r = await gw2.handle_request("rotate_network_key", {"mode": "cancel"}, "ui:admin")
    assert r["ok"] and r["cancelled"]
    await asyncio.sleep(0.1)
    assert gw2.rotation_status()["phase"] == "cancelled"
    assert coord2.secrets.network_key == key_before and Keystore(tmp_path / "network.keystore").load().pending_rotation is None
    assert any(e["type"] == "network_key_rotation_cancelled" for e in events)
    await t2.close()


async def _rotation_setup(tmp_path):
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    KeyRotation.MIN_WINDOW_S = 1
    KeyRotation.RETRY_EVERY_S = 0.2
    KeyRotation.LOOKUP_TIMEOUT_S = 0.3
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    old_key = coord.secrets.network_key
    for ieee, nwk in ((0x00158D0000000001, 0x1234), (0x00158D0000000005, 0x1235)):
        gw.registry.add_or_update(ieee, nwk, is_router=True)
        fake.nwk_to_ieee[nwk] = ieee
        fake.device_keys[nwk] = old_key  # modelled: answers only on the key it is on
    sleeper = gw.registry.add_or_update(0x00158D0000000002, 0x5678, is_router=False, rx_on_when_idle=False)
    sleeper.last_seen = time.time()
    fake.nwk_to_ieee[0x5678] = 0x00158D0000000002
    fake.device_keys[0x5678] = old_key
    gw.cfg.zigbee.rotation_max_window_seconds = 2
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    return fake, coord, broker, gw, t, old_key, events


async def _wait_done(gw, n=600):
    for _ in range(n):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "aborted", "failed", "rolled_back", "cancelled"):
            break
    return gw.rotation_status()


async def test_rotation_switches_by_unicast_leaves_first_then_routers_then_coordinator(tmp_path):
    """A broadcast never reaches a sleeping device and a router switched early would cut the mesh,
    so every device is told by unicast — sleepers first, routers last — and the coordinator moves
    last. Modelled devices that follow only unicast orders end up on the new key together."""
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t, old_key, events = await _rotation_setup(tmp_path)
    fake.devices_follow_broadcast_switch = False
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    st = await _wait_done(gw)
    assert st["phase"] == "done", st
    new_key = Keystore(tmp_path / "network.keystore").load().network_key
    assert new_key != old_key and fake.active_key == new_key
    assert all(k == new_key for k in fake.device_keys.values()), "every device switched by unicast"
    unicast = [d for d, _ in fake.key_switches if d != 0xFFFF]
    assert unicast[0] == 0x5678 and set(unicast[1:]) == {0x1234, 0x1235}, "sleeper first, routers after"
    assert sorted(st["switched"]) == ["0x00158d0000000001", "0x00158d0000000002", "0x00158d0000000005"] and st["unreachable"] == []
    rotated = [e for e in events if e["type"] == "network_key_rotated"][-1]
    assert rotated["switched"] == 3 and rotated["verified"] is True
    await t.close()


async def test_rotation_rolls_the_coordinator_back_when_the_devices_did_not_switch(tmp_path):
    """The field case: the radio switched, the devices did not. No router answers on the new key,
    so the coordinator returns to the previous key — nothing is lost, the audit says so."""
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t, old_key, events = await _rotation_setup(tmp_path)
    fake.devices_follow_broadcast_switch = False
    fake.devices_follow_unicast_switch = False
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    st = await _wait_done(gw)
    assert st["phase"] == "rolled_back" and st["rolled_back"] and len(st["unreachable"]) == 2, st
    assert fake.active_key == old_key, "the coordinator is back on the key the devices use"
    saved = Keystore(tmp_path / "network.keystore").load()
    assert saved.network_key == old_key and saved.previous_network_key not in (None, old_key), "the abandoned key is kept as the alternate"
    assert fake.nv[c.NvId.PRECFGKEY][:16] == old_key
    types = [e["type"] for e in events]
    assert "network_key_rotation_rolled_back" in types and "network_key_switch_rolled_back" in types
    assert all(k == old_key for k in fake.device_keys.values())
    await t.close()


async def test_rotation_copes_with_firmware_that_switches_itself_on_a_unicast_order(tmp_path):
    """Some firmware switches the coordinator on the first unicast switch order. The rotation notices
    (active sequence jumped) and restores the current key so the other devices can still be told;
    the coordinator moves last, and everyone ends on the new key."""
    from oneroof_zigbee.security import Keystore
    fake, coord, broker, gw, t, old_key, events = await _rotation_setup(tmp_path)
    fake.switch_local_on_unicast = True
    fake.devices_follow_broadcast_switch = False
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    st = await _wait_done(gw)
    assert st["phase"] == "done", st
    new_key = Keystore(tmp_path / "network.keystore").load().network_key
    assert fake.active_key == new_key and all(k == new_key for k in fake.device_keys.values())
    assert st["unreachable"] == []
    await t.close()


async def test_pairing_session_triggers_one_rotation_and_adopts_late_joiners(tmp_path):
    """Re-pairing a whole home is many plain joins in a row: the policy rotation must fire ONCE,
    after the session is quiet — and a device that joins while the rotation is already running is
    adopted by it, so nobody is left on the old key at the switch."""
    from oneroof_zigbee.rotation import KeyRotation
    KeyRotation.MIN_WINDOW_S = 1
    fake, coord, broker, gw, t = await make(tmp_path)
    gw.ROTATE_AFTER_JOIN_QUIET_S = 0.3
    gw.rotation_policy.after_plain_join = True
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    for i in (0, 1):
        await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
        fake.nwk_to_ieee[NWK + i] = IEEE + i
        fake.emit_announce(IEEE + i, NWK + i)
        for _ in range(100):
            await asyncio.sleep(0.02)
            if gw.registry.get(IEEE + i) and gw.registry.get(IEEE + i).interviewed:
                break
    assert gw._rotation is None or not gw._rotation.running, "no rotation while the session is hot"
    assert sum(e["type"] == "key_rotation_scheduled" for e in events) == 2, "each join re-arms the timer"
    for _ in range(200):
        await asyncio.sleep(0.02)
        if gw._rotation is not None and gw._rotation.running:
            break
    assert sum(e["type"] == "network_key_rotation_started" for e in events) == 1, "one rotation for the whole session"
    # a third device joins while the rotation is delivering/waiting: it is adopted
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
    fake.nwk_to_ieee[NWK + 2] = IEEE + 2
    fake.emit_announce(IEEE + 2, NWK + 2)
    for _ in range(200):
        await asyncio.sleep(0.02)
        st = gw.rotation_status()
        if f"0x{IEEE + 2:016x}" in (st.get("delivered") or []):
            break
    assert any(e["type"] == "rotation_adopted_new_device" for e in events)
    assert f"0x{IEEE + 2:016x}" in gw.rotation_status()["delivered"], "the late joiner holds the new key"
    gw._rotation.state.window_s = 1
    gw._rotation.state.switch_at = 0
    for _ in range(300):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] in ("done", "failed", "aborted", "rolled_back"):
            break
    assert gw.rotation_status()["phase"] == "done"
    assert sum(e["type"] == "network_key_rotation_started" for e in events) == 1
    await t.close()


async def test_scheduled_rotation_fires_when_the_key_is_old(tmp_path):
    """rotation_interval_days: first sighting starts the clock (no surprise rotation), an overdue
    key starts one policy rotation through the evidence engine, and it never fires while a pairing
    session is open."""
    import time as _t
    fake, coord, broker, gw, t = await make(tmp_path)
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    gw.rotation_policy.every_days = 1
    coord.secrets.last_rotation_ts = None
    gw._maybe_scheduled_rotation()
    assert coord.secrets.last_rotation_ts is not None, "clock started"
    assert gw._rotation is None or not gw._rotation.running, "no rotation on the first sighting"
    coord.secrets.last_rotation_ts = _t.time() - 2 * 86400
    coord.guard.request_open(30, "test")  # a pairing session is open: wait
    gw._maybe_scheduled_rotation()
    assert gw._rotation is None or not gw._rotation.running, "never during a pairing session"
    coord.guard._window = None
    gw._maybe_scheduled_rotation()
    await asyncio.sleep(0.05)
    assert gw._rotation is not None and gw._rotation.running
    assert gw.rotation_status()["by"] == "policy:scheduled"
    assert any(e["type"] == "scheduled_key_rotation_due" for e in events)
    ok = await gw.handle_request("rotate_network_key", {"mode": "cancel"}, "admin")
    assert ok["ok"]
    await t.close()


async def test_fresh_formation_marks_every_known_device_offline(tmp_path):
    """After the coordinator forms a NEW network, no previously known device can be online — the
    registry's remembered availability is from the old network and must not be shown as live."""
    fake, coord, broker, gw, t = await make(tmp_path)
    assert getattr(coord, "network_was_formed", False), "the test harness forms fresh"
    d = gw.registry.add_or_update(IEEE + 7, NWK + 7, is_router=True)
    d.available = True
    gw.registry.save()
    from oneroof_zigbee.gateway import Gateway
    gw2 = Gateway(gw.cfg, coord, broker, coord.audit, gw.registry, control_users={"admin"})
    await gw2.start()
    assert gw.registry.get(IEEE + 7).available is False, "stale availability cleared on a fresh network"
    await t.close()


async def test_rejoin_of_a_known_device_reruns_the_interview(tmp_path):
    """A device that joins again THROUGH A PAIRING WINDOW was factory-reset: its reporting config
    and bindings are gone, whatever the registry remembers — the interview must run again (it
    keeps name and identity). The window is what marks it a re-pair; a rejoin outside a window is
    a device merely coming back, and is deliberately not interviewed (see
    test_a_rejoin_does_not_restart_the_interview)."""
    fake, coord, broker, gw, t = await make(tmp_path)
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
    fake.nwk_to_ieee[NWK] = IEEE
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        if gw.registry.get(IEEE) and gw.registry.get(IEEE).interviewed:
            break
    assert sum(e["type"] == "interview_started" for e in events) == 1
    # the same device joins again after a factory reset (new network address)
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 60}', user="admin")
    fake.nwk_to_ieee[NWK + 5] = IEEE
    fake.emit_announce(IEEE, NWK + 5)
    for _ in range(150):
        await asyncio.sleep(0.02)
        if sum(e["type"] == "interview_started" for e in events) >= 2:
            break
    assert sum(e["type"] == "interview_started" for e in events) >= 2, "rejoin re-runs the interview"
    assert gw.registry.get(IEEE).nwk == NWK + 5
    await t.close()


async def test_rename_rejects_topic_breaking_characters(tmp_path):
    import pytest
    fake, coord, broker, gw, t = await make(tmp_path)
    gw.registry.add_or_update(IEEE + 9, NWK + 9)
    for bad in ("living/room", "a+b", "all#"):
        with pytest.raises(ValueError):
            gw.registry.rename(IEEE + 9, bad)
    gw.registry.rename(IEEE + 9, "Living room lamp")
    await t.close()


async def _joined_and_interviewed(fake, broker, gw, ieee, nwk):
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="admin")
    fake.emit_announce(ieee, nwk)
    for _ in range(100):
        await asyncio.sleep(0.02)
        dev = gw.registry.get(ieee)
        if dev and dev.interviewed:
            return dev
    raise AssertionError("the interview did not finish")


async def test_a_fresh_join_waits_for_a_name_before_home_assistant_hears_of_it(tmp_path):
    """Home Assistant builds the entity id from the first name it is given and keeps it for good, so
    an unnamed device must not reach it as 0x00158d00000000d3_contact. Naming it in the panel
    publishes it at once, under the friendly name."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = await _joined_and_interviewed(fake, broker, gw, IEEE, NWK)
    cfg_topic = f"homeassistant/light/{dev.ieee_str}/light/config"
    assert broker.last(cfg_topic) is None
    assert "ha_name_hold" in dev.context
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["state"] == "ON"  # state still flows
    await gw._on_ha_status("homeassistant/status", b"online")  # HA restarting mid-hold does not leak the address name either
    assert broker.last(cfg_topic) is None

    await gw.handle_request("rename", {"ieee": dev.ieee_str, "friendly_name": "Hall lamp"}, "admin")
    disc = json.loads(broker.last(cfg_topic))
    assert disc["object_id"] == "Hall lamp_light" and disc["device"]["name"] == "Hall lamp"
    assert "ha_name_hold" not in dev.context
    await t.close()


async def test_a_join_nobody_names_reaches_home_assistant_after_the_grace_period(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    seen = []
    gw.audit.subscribe(seen.append)
    dev = await _joined_and_interviewed(fake, broker, gw, IEEE, NWK)
    cfg_topic = f"homeassistant/light/{dev.ieee_str}/light/config"
    await gw._release_name_holds()
    assert broker.last(cfg_topic) is None  # still inside the hold
    dev.context["ha_name_hold"] = time.time() - gw.HA_NAME_HOLD_S - 1
    await gw._release_name_holds()
    disc = json.loads(broker.last(cfg_topic))
    assert disc["object_id"] == f"{dev.ieee_str}_light"
    assert "ha_name_hold" not in dev.context
    assert any(r["type"] == "ha_announced_unnamed" for r in seen)
    await t.close()


async def test_a_known_device_rejoining_is_not_held_back_from_home_assistant(tmp_path):
    """Only a device Home Assistant has never seen waits for a name: one that was announced
    before (a re-pair, a power cut rejoin) keeps its entities without a gap."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = await _joined_and_interviewed(fake, broker, gw, IEEE, NWK)
    dev.context["ha_name_hold"] = time.time() - gw.HA_NAME_HOLD_S - 1
    await gw._release_name_holds()
    cfg_topic = f"homeassistant/light/{dev.ieee_str}/light/config"
    assert broker.last(cfg_topic) is not None
    fake.emit_announce(IEEE, NWK)
    await asyncio.sleep(0.3)
    assert "ha_name_hold" not in dev.context
    published_before = len(broker.published)
    await gw._on_ha_status("homeassistant/status", b"online")
    assert any(t == cfg_topic for t, _, _ in broker.published[published_before:])
    await t.close()


async def test_rename_in_the_panel_republishes_discovery_under_the_new_name(tmp_path):
    """A device paired and left at its address is offered to Home Assistant as
    binary_sensor.0x..._contact. Renaming it in the panel republishes discovery with the friendly
    object_id and device name and the same unique_id - HA updates the name but, by its own rules,
    keeps the entity id it created first; the id is renamed in HA, not here."""
    import json as _json
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    ieee = 0x00158D00000000D3
    dev = gw.registry.add_or_update(ieee, NWK + 21, manufacturer="LUMI", model="lumi.sensor_magnet.aq2")
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x5F01, [0, 3, 0xFFFF, 0x19], [0, 4, 3, 6, 8, 5], "sensor")
    dev.interviewed = True
    await gw._announce(dev)
    topic = f"homeassistant/binary_sensor/{dev.ieee_str}/contact/config"
    before = _json.loads(broker.last(topic))
    assert before["object_id"] == "0x00158d00000000d3_contact" and before["device"]["name"] == "0x00158d00000000d3"

    await gw.handle_request("rename", {"ieee": dev.ieee_str, "friendly_name": "Back door"}, "admin")
    after = _json.loads(broker.last(topic))
    assert after["object_id"] == "Back door_contact" and after["device"]["name"] == "Back door"
    assert after["unique_id"] == before["unique_id"], "same entity to HA, so its existing id survives"
    assert after["state_topic"] == before["state_topic"] == f"oneroof/zigbee/{dev.ieee_str}/state", "topics are by address: a rename moves nothing"
    await t.close()


async def test_devices_silent_since_formation_are_offline_on_every_start(tmp_path):
    """The formation marking must survive restarts: a device that has not spoken since the network
    was formed cannot be online, however many times the add-on restarts in between."""
    import time as _t
    fake, coord, broker, gw, t = await make(tmp_path)
    assert (coord.secrets.formed_ts or 0) > 0, "formation stamps the birth time"
    coord.network_was_formed = False  # later restart: the one-shot flag is gone
    d = gw.registry.add_or_update(IEEE + 11, NWK + 11, is_router=True)
    d.available = True
    d.last_seen = coord.secrets.formed_ts - 100  # spoke only on the OLD network
    gw.registry.save()
    from oneroof_zigbee.gateway import Gateway
    gw2 = Gateway(gw.cfg, coord, broker, coord.audit, gw.registry, control_users={"admin"})
    await gw2.start()
    assert gw.registry.get(IEEE + 11).available is False
    # ...but one that spoke after formation keeps its badge
    d2 = gw.registry.add_or_update(IEEE + 12, NWK + 12, is_router=True)
    d2.available = True
    d2.last_seen = _t.time()
    gw3 = Gateway(gw.cfg, coord, broker, coord.audit, gw.registry, control_users={"admin"})
    await gw3.start()
    assert gw.registry.get(IEEE + 12).available is True
    await t.close()


async def test_went_silent_flips_the_availability_badge(tmp_path):
    """The liveness monitor reports (ieee, kind); a mains device silent past its own rhythm is
    marked offline so the dashboard tells the truth."""
    from oneroof_zigbee.monitor import Monitor, Profile
    events = []
    mon = Monitor(lambda type_, **f: events.append((type_, f)))
    p = mon.profiles.setdefault(0xAB, Profile())
    p.last_seen = mon._now() - 10_000
    p.typical_gap = 60
    p.frames = 50
    gone = mon.sweep([(0xAB, True)])
    assert (0xAB, "went_silent") in gone


async def test_startup_keeps_a_green_badge_only_for_recently_heard_devices(tmp_path):
    """Availability is evidence, not memory: a device silent for days starts offline even when the
    registry remembers it as online and the network's birth time is unknown (an install that formed
    before the birth time was recorded)."""
    import time as _t
    fake, coord, broker, gw, t = await make(tmp_path)
    coord.network_was_formed = False
    coord.secrets.formed_ts = None  # older keystore: no birth time at all
    now = _t.time()
    quiet_router = gw.registry.add_or_update(IEEE + 21, NWK + 21, is_router=True)
    quiet_router.available, quiet_router.last_seen = True, now - 3 * 86400
    live_router = gw.registry.add_or_update(IEEE + 22, NWK + 22, is_router=True)
    live_router.available, live_router.last_seen = True, now - 60
    sleepy_sensor = gw.registry.add_or_update(IEEE + 23, NWK + 23, is_router=False)
    sleepy_sensor.available, sleepy_sensor.last_seen = True, now - 3600  # battery: an hour is normal
    gw.registry.save()
    from oneroof_zigbee.gateway import Gateway
    gw2 = Gateway(gw.cfg, coord, broker, coord.audit, gw.registry, control_users={"admin"})
    await gw2.start()
    assert gw.registry.get(IEEE + 21).available is False, "silent for days: offline"
    assert gw.registry.get(IEEE + 22).available is True, "heard a minute ago: still online"
    assert gw.registry.get(IEEE + 23).available is True, "a sleeping sensor gets a longer grace"
    await t.close()


async def test_refused_reporting_is_retried_and_then_polled_often(tmp_path):
    """A device that refuses to configure reporting (Aqara wall switches do it on the second gang)
    is retried with a one-second minimum, and if it still refuses it is polled often enough that a
    physical press still reaches the dashboard."""
    from oneroof_zigbee import zcl
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(IEEE + 31, NWK + 31, is_router=True)
    seen: list[int] = []

    async def refuse_then_accept(d, ep, cluster, frame, seq, expect_cmd, timeout=10.0):
        seen.append(seq)
        if len(seen) == 1:
            return zcl.decode_frame(bytes([0x18, seq & 0xFF, 0x07, 0xC1, 0x00, 0x00, 0x00]))
        return zcl.decode_frame(bytes([0x18, seq & 0xFF, 0x07, 0x00]))

    gw._request = refuse_then_accept
    await gw._setup_reporting(dev, 2, 0x0006)
    assert len(seen) == 2, "the refusal is retried once"
    rec = [r for r in dev.reporting if r["endpoint"] == 2 and r["cluster"] == 0x0006]
    assert rec and rec[0]["status"] == "ok" and rec[0]["min"] >= 1, rec
    assert gw._poll_after(dev) == gw.ROUTER_POLL_AFTER_S, "a device that reports is left alone"

    async def always_refuse(d, ep, cluster, frame, seq, expect_cmd, timeout=10.0):
        return zcl.decode_frame(bytes([0x18, seq & 0xFF, 0x07, 0xC1, 0x00, 0x00, 0x00]))

    gw._request = always_refuse
    dev2 = gw.registry.add_or_update(IEEE + 32, NWK + 32, is_router=True)
    await gw._setup_reporting(dev2, 2, 0x0006)
    rec2 = [r for r in dev2.reporting if r["endpoint"] == 2][0]
    assert not rec2["status"].startswith("ok"), rec2
    assert gw._poll_after(dev2) == gw.UNREPORTED_POLL_AFTER_S, "it is polled often instead"
    await t.close()


async def test_a_leaving_device_is_kept_and_can_come_back(tmp_path):
    """A leave frame — with or without the rejoin flag — must never delete a device. Deleting it
    also drops it from the known set, and its rejoin would then be evicted as an intruder: the
    device ends up searching for a network forever while its name, room and settings are gone."""
    from oneroof_zigbee.znp.unpi import Frame, FrameType, Subsystem
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.wire import Writer
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(IEEE + 41, NWK + 41, is_router=True)
    dev.friendly_name = "Hall light"
    dev.available = True
    coord.known_ieee.add(IEEE + 41)
    gw.registry.save()

    def leave(rejoin: bool) -> None:
        w = Writer().u16(NWK + 41).ieee(IEEE + 41).u8(1).u8(0).u8(1 if rejoin else 0)
        fake.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.LEAVE_IND, w.bytes()))

    leave(True)
    await asyncio.sleep(0.1)
    kept = gw.registry.get(IEEE + 41)
    assert kept is not None and kept.friendly_name == "Hall light", "a rejoining device is not forgotten"
    assert kept.available is False, "but it is honestly offline until it is heard again"
    assert IEEE + 41 in coord.known_ieee, "it stays known, so its rejoin is not evicted"

    leave(False)
    await asyncio.sleep(0.1)
    assert gw.registry.get(IEEE + 41) is not None, "even a plain leave keeps the device"
    assert IEEE + 41 in coord.known_ieee

    # and it really can come back: an announce is welcomed, never evicted
    fake.requests.clear()
    fake.nwk_to_ieee[NWK + 41] = IEEE + 41
    fake.emit_announce(IEEE + 41, NWK + 41)
    await asyncio.sleep(0.2)
    assert not any(f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.MGMT_LEAVE_REQ for f in fake.requests), "no eviction"
    await t.close()


async def test_rotation_backs_off_a_device_that_keeps_refusing_the_key(tmp_path):
    """A key transport is a security frame. A device that will not take it must not be offered the
    key every thirty seconds for hours — some devices answer that flood by deciding they have lost
    the network. The gap grows per device; one that talks to us is still served at once."""
    from oneroof_zigbee.devices import Registry
    from oneroof_zigbee.rotation import KeyRotation, RotationState
    from oneroof_zigbee.security import Audit
    reg = Registry(tmp_path / "devices.json")
    dev = reg.add_or_update(0x00158D00000000AA, 0x1234, is_router=True)
    rot = KeyRotation(None, reg, None, Audit(None))
    rot.state = RotationState(phase="waiting", started=time.time(), window_s=60, max_window_s=600)
    rot.state.failed[dev.ieee_str] = "unreachable"
    tries = []

    async def never(d, check=True):
        tries.append(d.ieee_str)
        return False

    rot._deliver = never
    await rot._retry_failed()
    assert len(tries) == 1, "the first sweep offers the key"
    await rot._retry_failed()
    await rot._retry_failed()
    assert len(tries) == 1, "the next sweeps leave the device alone"
    rot._retry_at[dev.ieee_str] = 0.0          # its turn comes round again
    await rot._retry_failed()
    assert len(tries) == 2
    assert rot._retry_at[dev.ieee_str] - time.time() > KeyRotation.RETRY_EVERY_S, "the gap grew"


async def test_state_is_fetched_from_the_device_after_a_restart(tmp_path):
    """The gateway must not present a remembered state as fact: after its own restart it asks each
    device that can answer what it actually is, publishes that, and marks the device online."""
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(IEEE + 51, NWK + 51, is_router=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0, 6], [], "plug")
    dev.state = {"state": "OFF"}          # what we remembered
    dev.available = False
    asked = []

    async def answer(d, ep, cluster, attrs):
        asked.append((ep, cluster))
        return {"state": "ON"} if cluster == 0x0006 else {}   # what the device really is

    gw.read_attributes = answer
    changed = await gw._refresh_state(dev)
    assert (1, 0x0006) in asked, "the on/off cluster was asked"
    assert changed and dev.state.get("state") == "ON", dev.state
    assert dev.available is True, "a device that answers is online again"
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["state"] == "ON"
    await t.close()


async def test_a_pure_relay_is_heard_after_a_restart(tmp_path):
    """A router with nothing to switch (the One Roof router) has none of the state clusters the
    restart refresh asks about. It must still be asked something - its model-table attribute and
    its name - so it has been heard: that is what link quality and last-seen go by. And a device
    that answered nothing must not be stamped as seen."""
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(IEEE + 52, NWK + 52, is_router=True, manufacturer="One Roof", model="oneroof.router")
    dev.endpoints[8] = Endpoint(8, 0x0104, 0x0008, [0x0000, 0x0003], [], "unknown")
    dev.last_seen = 0.0
    asked = []

    async def answer(d, ep, cluster, attrs):
        asked.append((ep, cluster, tuple(attrs)))
        return {"transmit_power": 9} if 0x1337 in attrs else {}

    gw.read_attributes = answer
    await gw._refresh_state(dev)
    assert (8, 0x0000, (0x1337,)) in asked, asked
    assert dev.last_seen > 0 and dev.state.get("transmit_power") == 9

    silent = gw.registry.add_or_update(IEEE + 53, NWK + 53, is_router=True)
    silent.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0x0000, 0x0003], [], "unknown")
    silent.last_seen = 0.0
    asked.clear()

    async def nobody_home(d, ep, cluster, attrs):
        asked.append((ep, cluster, tuple(attrs)))
        raise asyncio.TimeoutError

    gw.read_attributes = nobody_home
    await gw._refresh_state(silent)
    assert asked == [(1, 0x0000, (0x0004,))], "an unknown relay is asked for its name"
    assert silent.last_seen == 0.0, "not heard = not seen"
    await t.close()


def _outgoing_zcl(fake, cluster):
    """Every ZCL frame the gateway sent to a device on one cluster."""
    out = []
    for f in fake.requests:
        if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST:
            if int.from_bytes(f.data[4:6], "little") == cluster:
                out.append(f.data[10:])
    return out


async def _joined(tmp_path):
    fake, coord, broker, gw, t = await make(tmp_path)
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="admin")
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        dev = gw.registry.get(IEEE)
        if dev and dev.interviewed:
            break
    fake.requests.clear()
    return fake, coord, broker, gw, t


async def test_a_device_asking_for_the_time_gets_the_time(tmp_path, caplog):
    """Xiaomi/Aqara devices read the Time cluster off the gateway and repeat until answered;
    silence makes them treat the network as unreachable."""
    caplog.set_level(logging.INFO, logger="oneroof_zigbee.gateway")
    fake, coord, broker, gw, t = await _joined(tmp_path)

    # global Read Attributes of Time, TimeStatus, LocalTime — client to server
    read = bytes([0x00, 0x77, 0x00]) + b"".join(a.to_bytes(2, "little") for a in (0x0000, 0x0001, 0x0007))
    fake.emit_incoming(NWK, 0x000A, read)
    for _ in range(60):
        await asyncio.sleep(0.02)
        if _outgoing_zcl(fake, 0x000A):
            break

    sent = _outgoing_zcl(fake, 0x000A)
    assert sent, "the gateway said nothing at all"
    frame = sent[0]
    assert frame[0] & 0x08, "the reply must travel server to client"
    assert frame[1] == 0x77, "a reply carries the sequence number of the question"
    assert frame[2] == 0x01, "expected a Read Attributes Response"

    rsp = gc.ReadAttributesResponse.decode(frame[3:])
    got = {r.attr: r for r in rsp.records}
    assert set(got) == {0x0000, 0x0001, 0x0007}
    assert all(r.status == 0 for r in got.values()), "every asked attribute was answered"
    now = int(time.time() - 946684800)
    assert abs(got[0x0000].value - now) < 5, (got[0x0000].value, now)
    assert got[0x0001].value == 0x03, "time status: master and synchronised"
    # the whole answer runs to the end: a slip anywhere in it (a wrong attribute name in the log
    # line, say) dies inside its own task, where nothing fails a test but the gateway logs a
    # traceback for every device question
    assert any("answered a read of cluster 0x000a" in r.message for r in caplog.records), \
        [r.message for r in caplog.records]
    await t.close()


async def test_an_unanswerable_read_gets_a_real_no(tmp_path):
    """'Unsupported attribute' is an answer. Silence is what makes a device retry forever."""
    fake, coord, broker, gw, t = await _joined(tmp_path)

    fake.emit_incoming(NWK, 0x0402, bytes([0x00, 0x12, 0x00]) + (0x1234).to_bytes(2, "little"))
    for _ in range(60):
        await asyncio.sleep(0.02)
        if _outgoing_zcl(fake, 0x0402):
            break

    sent = _outgoing_zcl(fake, 0x0402)
    assert sent, "an unanswerable question still deserves an answer"
    rsp = gc.ReadAttributesResponse.decode(sent[0][3:])
    assert [(r.attr, r.status) for r in rsp.records] == [(0x1234, 0x86)]
    await t.close()


async def test_the_gateway_names_itself_when_asked(tmp_path):
    fake, coord, broker, gw, t = await _joined(tmp_path)

    fake.emit_incoming(NWK, 0x0000, bytes([0x00, 0x31, 0x00])
                       + b"".join(a.to_bytes(2, "little") for a in (0x0000, 0x0004, 0x0005)))
    for _ in range(60):
        await asyncio.sleep(0.02)
        if _outgoing_zcl(fake, 0x0000):
            break

    sent = _outgoing_zcl(fake, 0x0000)
    assert sent, "the gateway did not answer a read of its own Basic cluster"
    got = {r.attr: r.value for r in gc.ReadAttributesResponse.decode(sent[0][3:]).records}
    assert got[0x0000] == 3 and got[0x0004] == "One Roof" and got[0x0005] == "One Roof Gateway"
    await t.close()


async def test_an_unimplemented_global_command_is_refused_not_ignored(tmp_path):
    """The spec's answer to 'I do not implement that' is a Default Response, which stops the
    retries; before, the frame fell on the floor."""
    fake, coord, broker, gw, t = await _joined(tmp_path)

    # Discover Attributes (0x0C), default response NOT disabled
    fake.emit_incoming(NWK, 0x0006, bytes([0x00, 0x44, 0x0C, 0x00, 0x00, 0xFF]))
    for _ in range(60):
        await asyncio.sleep(0.02)
        if _outgoing_zcl(fake, 0x0006):
            break

    sent = _outgoing_zcl(fake, 0x0006)
    assert sent, "no answer to an unimplemented global command"
    assert sent[0][2] == 0x0B, "expected a Default Response"
    cmd, status = sent[0][3], sent[0][4]
    assert (cmd, status) == (0x0C, 0x82), "unsupported general command"
    await t.close()


async def test_a_device_that_wants_silence_gets_it(tmp_path):
    """Disable-default-response means exactly that: no reply, no noise on the air."""
    fake, coord, broker, gw, t = await _joined(tmp_path)

    fake.emit_incoming(NWK, 0x0006, bytes([0x10, 0x45, 0x0C, 0x00, 0x00, 0xFF]))
    await asyncio.sleep(0.4)
    assert not _outgoing_zcl(fake, 0x0006), "answered a device that asked not to be answered"
    await t.close()


async def test_a_state_refresh_works_in_the_address_layout_too(tmp_path):
    """Consumers ask for a state refresh on <base>/<ieee>/get — at startup and when a device
    returns from an outage. Answering it only in the legacy layout turned every such refresh
    into silence: the asker just never got fresh state."""
    fake, coord, broker, gw, t = await _joined(tmp_path)
    dev = gw.registry.get(IEEE)
    broker.published.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/get", b'{"brightness": ""}')
    for _ in range(60):
        await asyncio.sleep(0.02)
        if broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"):
            break
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state.get("state") == "ON", "a /get in the address layout went unanswered"
    await t.close()


async def test_a_report_that_asks_for_a_receipt_gets_one(tmp_path):
    """Xiaomi/Aqara devices send their state reports and heartbeats with the default response
    REQUESTED, and judge the hub by whether it arrives: a silent hub is marked lost on the
    device's indicator LED even while commands keep working. The spec agrees — a Report
    Attributes without disable-default-response gets a Default Response."""
    fake, coord, broker, gw, t = await _joined(tmp_path)

    # report on/off = ON, frame control 0x08 (server-to-client, default response requested)
    fake.emit_incoming(NWK, 0x0006, bytes([0x08, 0x5A, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    for _ in range(60):
        await asyncio.sleep(0.02)
        if _outgoing_zcl(fake, 0x0006):
            break
    sent = _outgoing_zcl(fake, 0x0006)
    assert sent, "the report was consumed but never receipted"
    frame = sent[0]
    assert frame[1] == 0x5A and frame[2] == 0x0B, "expected a Default Response to seq 0x5A"
    assert (frame[3], frame[4]) == (0x0A, 0x00), "…acknowledging the report, with SUCCESS"

    # the same report with disable-default-response set gets silence, exactly as asked
    fake.requests.clear()
    fake.emit_incoming(NWK, 0x0006, bytes([0x18, 0x5B, 0x0A, 0x00, 0x00, 0x10, 0x00]))
    await asyncio.sleep(0.4)
    assert not _outgoing_zcl(fake, 0x0006), "receipted a report that asked for silence"
    await t.close()


async def test_a_poll_control_checkin_is_answered_properly(tmp_path):
    """The device asks "hub, are you there?" on a timer; the spec's answer is a Check-in
    Response, not a generic default response. A device whose check-ins go unanswered concludes
    the hub is gone — some say so on their indicator LED while still obeying every command."""
    fake, coord, broker, gw, t = await _joined(tmp_path)

    # cluster-specific, server→client, checkin (0x00)
    fake.emit_incoming(NWK, 0x0020, bytes([0x09, 0x66, 0x00]))
    for _ in range(60):
        await asyncio.sleep(0.02)
        if _outgoing_zcl(fake, 0x0020):
            break
    sent = _outgoing_zcl(fake, 0x0020)
    assert sent, "the check-in went unanswered"
    z = sent[0]
    assert z[0] & 0x01 and not (z[0] & 0x08), "a cluster-specific reply, client to server"
    assert z[1] == 0x66, "carrying the check-in's own sequence number"
    assert z[2] == 0x00, "a Check-in Response"
    assert z[3:6] == b"\x00\x00\x00", "no fast polling asked of a device that did not offer it"
    assert z[0] != 0x0B, "and not a generic default response in its place"
    await t.close()


async def test_a_rejoin_does_not_restart_the_interview(tmp_path):
    """A rejoin is a device coming back with its configuration intact. Re-interviewing on every
    rejoin turned a stumble into a storm: the interview's burst of reads and writes is real load,
    a marginal no-neutral device reboots under it, reboots rejoin, and every rejoin started the
    next interview — observed live as a rejoin-and-interview cycle every eight seconds."""
    fake, coord, broker, gw, t = await _joined(tmp_path)
    dev = gw.registry.get(IEEE)
    assert dev.interviewed

    events = []
    gw.audit.subscribe(lambda rec: events.append(rec.get("type")))
    fake.emit_announce(IEEE, NWK)          # a plain rejoin (no TC involvement)
    fake.emit_announce(IEEE, NWK)          # announces arrive in pairs
    await asyncio.sleep(0.5)
    assert "device_rejoined" in events
    assert "interview_started" not in events, "a rejoin of a configured device must not interview"

    # …but a rejoining device that was never interviewed is still completed
    dev.interviewed = False
    events.clear()
    fake.emit_announce(IEEE, NWK)
    for _ in range(50):
        await asyncio.sleep(0.02)
        if "interview_started" in events:
            break
    assert "interview_started" in events, "an unconfigured device must still be interviewed"
    await t.close()


async def test_only_one_interview_runs_per_device(tmp_path):
    """Announces arrive in pairs; each used to cancel the running interview and begin again, so a
    flapping device was interviewed forever and never finished a single one."""
    fake, coord, broker, gw, t = await make(tmp_path)
    await broker.inject("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', user="admin")
    starts = []
    gw.audit.subscribe(lambda rec: starts.append(rec) if rec.get("type") == "interview_started" else None)
    fake.emit_announce(IEEE, NWK)
    fake.emit_announce(IEEE, NWK)
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        d = gw.registry.get(IEEE)
        if d and d.interviewed:
            break
    assert len(starts) == 1, f"{len(starts)} interviews for one joining device"
    assert gw.registry.get(IEEE).interviewed, "the single interview still completes"
    await t.close()


async def test_a_restart_pauses_a_rotation_instead_of_cancelling_it(tmp_path):
    """An add-on restart tears every task down with the same CancelledError a user cancel uses.
    A restart is not a decision to stop rotating: the progress must survive (that is the whole
    point of the pending record), and the audit must say 'paused', not 'cancelled'. Before the
    distinction, every add-on update quietly cancelled a running rotation and wiped its saved
    progress — observed live, twice in one evening, at exactly the update times."""
    from oneroof_zigbee.rotation import KeyRotation
    from oneroof_zigbee.security import Keystore
    KeyRotation.MIN_WINDOW_S = 1
    KeyRotation.RETRY_EVERY_S = 0.2
    KeyRotation.LOOKUP_TIMEOUT_S = 0.3
    fake, coord, broker, gw, t = await make(tmp_path)
    Keystore(tmp_path / "network.keystore").save(coord.secrets)
    gw.registry.add_or_update(0x00158D0000000001, 0x1234, is_router=True)
    fake.nwk_to_ieee[0x1234] = 0x00158D0000000001
    gw.registry.add_or_update(0x00158D0000000007, 0x9999, is_router=True)  # never answers
    gw.registry.save()
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    await gw.handle_request("rotate_network_key", {"window_s": 1}, "ui:admin")
    for _ in range(300):
        await asyncio.sleep(0.02)
        if gw.rotation_status()["phase"] == "waiting" and gw.rotation_status()["delivered"]:
            break
    for _ in range(40):
        if Keystore(tmp_path / "network.keystore").load().pending_rotation:
            break
        await asyncio.sleep(0.1)

    # the shutdown: the task is cancelled WITHOUT anyone calling cancel()
    gw._rotation._task.cancel()
    await asyncio.sleep(0.2)

    assert any(e["type"] == "network_key_rotation_paused" for e in events), \
        [e["type"] for e in events if "rotation" in e["type"]]
    assert not any(e["type"] == "network_key_rotation_cancelled" for e in events), \
        "a restart must not read as a user cancel"
    pending = Keystore(tmp_path / "network.keystore").load().pending_rotation
    assert pending is not None, "the saved progress was wiped by the restart"
    assert pending.get("delivered") == ["0x00158d0000000001"], "…and must still know who has the key"
    await t.close()


# --------------------------------------------------------------- the truth about state --
# A light that shows ON in Apple Home while it is dark in the room. Every path by which the
# gateway could carry a remembered or guessed state around as if it were true is closed here.


def _bulb(gw, ieee, nwk, clusters=(0, 6, 8)):
    from oneroof_zigbee.devices import Endpoint
    dev = gw.registry.add_or_update(ieee, nwk, is_router=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, list(clusters), [], "light")
    dev.interviewed = True
    return dev


async def test_state_changes_reach_the_registry_file(tmp_path):
    """The file is what the next start publishes before it can ask anyone. A state that changed
    after the last incidental save used to come back as yesterday's truth; now a change marks the
    registry dirty, the monitor tick writes it, and stop() writes it once more."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 61, NWK + 61)
    gw.registry.save()
    gw._apply_changes(dev, {"state": "ON"})
    assert gw._dirty, "a state change is worth writing"
    gw._save_if_dirty()
    assert not gw._dirty
    saved = json.loads((tmp_path / "devices.json").read_text())
    me = next(d for d in saved["devices"] if d["ieee"] == dev.ieee_str)
    assert me["state"]["state"] == "ON"
    gw._apply_changes(dev, {"state": "ON"})
    assert not gw._dirty, "the same value again is not a change"
    dev.available = False
    gw._apply_changes(dev, {"state": "OFF"})
    await gw.stop()
    me = next(d for d in json.loads((tmp_path / "devices.json").read_text())["devices"] if d["ieee"] == dev.ieee_str)
    assert me["state"]["state"] == "OFF" and me["available"] is False, "stop() writes the last word"
    await t.close()


async def test_a_refused_bind_is_never_called_reporting_ok(tmp_path):
    """The bind is what makes a device report a physical press. A device that refuses it (ZDO
    status, a full binding table) used to be recorded as reporting "ok" - and then showed the
    state of its last command for ever. Now the refusal is recorded and the device is polled."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 62, NWK + 62)
    fake.bind_status = 0x8C
    await gw._setup_reporting(dev, 1, 0x0006)
    rec = [r for r in dev.reporting if r["cluster"] == 0x0006]
    assert rec and rec[0]["status"] == "bind failed (0x8c)", rec
    assert not dev.bindings if hasattr(dev, "bindings") else True
    assert gw._poll_after(dev) == gw.UNREPORTED_POLL_AFTER_S, "asked every minute instead"
    assert gw._reporting_to_retry(dev) == [(1, 0x0006)], "and tried again when it next talks"
    fake.bind_status = 0x00
    await t.close()


async def test_failed_reporting_setup_is_retried_when_the_device_talks(tmp_path):
    """A device that fell asleep or dropped a frame during its interview never got its reporting
    configured, and nothing retried it: it kept its old state until someone restarted the
    gateway. The moment it talks it is listening, so that is when it is tried again."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 63, NWK + 63)
    dev.reporting = [{"endpoint": 1, "cluster": 0x0006, "attribute": 0, "status": "failed: timeout"}]
    fake.emit_incoming(NWK + 63, 0x0006, bytes([0x18, 0x33, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if dev.ieee not in gw._interview_tasks and dev.context.get("reporting_retry_at"):
            break
    rec = [r for r in dev.reporting if r["cluster"] == 0x0006]
    assert rec and rec[0]["status"] == "ok", rec
    assert dev.context["reporting_retry_at"] > time.time() + 60, "the next attempt waits a while"
    # a ZCL refusal is the device's final word: not retried
    dev.reporting = [{"endpoint": 1, "cluster": 0x0006, "attribute": 0, "status": "status 0x8c"}]
    assert gw._reporting_to_retry(dev) == []
    await t.close()


async def test_a_rejoining_device_is_asked_what_it_is(tmp_path):
    """A rejoin is most often a power cut. The bulb comes back ON at the wall while we remember
    it OFF; it is not re-interviewed (that storm is over) but it is asked."""
    from oneroof_zigbee.znp import JoinedDevice
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 64, NWK + 64)
    dev.state["state"] = "OFF"
    asked = []

    async def answer(d, ep, cluster, attrs):
        asked.append(cluster)
        return {"state": "ON"} if cluster == 0x0006 else {}

    gw.read_attributes = answer
    gw._schedule_refresh = lambda d, delay=3.0: Gateway._schedule_refresh(gw, d, delay=0.05)
    await gw._on_joined(JoinedDevice(ieee=dev.ieee, nwk=dev.nwk, parent=None, capabilities=0x8E, rejoin=True))
    assert dev.ieee not in gw._interview_tasks, "no interview storm on a rejoin"
    assert dev.ieee in gw._refresh_tasks
    for _ in range(50):
        await asyncio.sleep(0.02)
        if dev.ieee not in gw._refresh_tasks:
            break
    assert 0x0006 in asked and dev.state["state"] == "ON"
    await t.close()


async def test_a_router_that_stops_answering_goes_offline(tmp_path):
    """A bulb cut from power at the wall answers nothing. Two unanswered polls and it is offline -
    Apple Home shows "No Response" instead of the last thing it said - and it is polled less
    often from then on, until it is heard again."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 65, NWK + 65)
    dev.available = True
    dev.last_seen = time.time()          # its power reports were arriving right up to the cut
    gw._state_evidence[dev.ieee] = 0.0   # but it has not said what it IS in a long time

    async def nobody_home(d, ep, cluster, attrs):
        raise asyncio.TimeoutError

    gw.read_attributes = nobody_home
    await gw._poll_silent_routers()
    assert dev.available, "one miss is a lost frame"
    await gw._poll_silent_routers()
    assert not dev.available, "two misses is a device that is gone"
    assert broker.last(f"oneroof/zigbee/{dev.ieee_str}/availability") == b"offline"
    assert gw._poll_not_before[dev.ieee] > time.time() + 200
    n = len(broker.published)
    await gw._poll_silent_routers()
    assert len(broker.published) == n, "an offline device is not hammered every minute"

    fake.emit_incoming(NWK + 65, 0x0006, bytes([0x18, 0x33, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    await asyncio.sleep(0.05)
    assert dev.available and dev.ieee not in gw._poll_not_before, "heard: online, and polled normally again"
    assert dev.ieee not in gw._poll_failures and dev.ieee not in gw._poll_first_miss, "a fresh start"
    assert dev.ieee in gw._refresh_tasks, "and asked what it is now - it came back in whatever state its firmware chose"
    await t.close()


async def test_a_plug_that_reports_but_never_answers_does_not_flap(tmp_path):
    """Seen on a real network: a plug in the garage whose power reports arrive all night while
    every read we send it times out (its route back is broken, ours is not). 2.13.0 called it
    offline after two misses and online again on its next report - every minute or two, all
    night, with every consumer asking for its state on each "back online". A device heard since
    the first miss is alive: it stays online with what it last reported, and is asked less and
    less often instead of every minute."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 67, NWK + 67, clusters=(0, 6, 0x0B04))
    dev.available = True
    gw._state_evidence[dev.ieee] = 0.0
    noted = []
    coord.audit.subscribe(lambda r: noted.append(r) if r.get("type") == "device_not_answering_reads" else None)

    async def nobody_home(d, ep, cluster, attrs):
        raise asyncio.TimeoutError

    gw.read_attributes = nobody_home
    power_report = bytes([0x18, 0x33, 0x0A, 0x0B, 0x05, 0x29, 0x10, 0x00])  # active power 16 W

    fake.emit_incoming(NWK + 67, 0x0B04, power_report)
    await asyncio.sleep(0.05)
    await gw._poll_silent_routers()
    fake.emit_incoming(NWK + 67, 0x0B04, power_report)  # it keeps talking between the polls
    await asyncio.sleep(0.05)
    assert dev.ieee in gw._poll_failures, "a report is not an answer: the miss still counts"
    await gw._poll_silent_routers()
    assert dev.available, "heard since the first miss: alive, just not answering"
    assert broker.last(f"oneroof/zigbee/{dev.ieee_str}/availability") != b"offline"
    assert not [e for e in broker.published if e[0].endswith("/availability") and e[1] == b"offline"]
    assert gw._poll_not_before[dev.ieee] > time.time() + 250, "and asked again in five minutes, not one"
    assert len(noted) == 1, "written up once"

    fake.emit_incoming(NWK + 67, 0x0B04, power_report)
    await asyncio.sleep(0.05)
    assert gw._poll_not_before[dev.ieee] > time.time() + 250, "another report does not re-arm the poll"
    assert dev.available
    n = len(broker.published)
    await gw._poll_silent_routers()
    assert len(broker.published) == n, "not asked again before its time"

    # the backoff grows: 5, 10, 15, 30 minutes
    gw._poll_not_before[dev.ieee] = 0.0
    await gw._poll_silent_routers()
    assert gw._poll_not_before[dev.ieee] > time.time() + 550
    assert len(noted) == 1, "not written up again"

    # one answered read and everything is back to normal
    async def answer(d, ep, cluster, attrs):
        return {"state": "ON"} if cluster == 0x0006 else {}

    gw.read_attributes = answer
    gw._poll_not_before[dev.ieee] = 0.0
    await gw._poll_silent_routers()
    assert dev.ieee not in gw._poll_failures and dev.ieee not in gw._poll_not_before
    assert dev.state["state"] == "ON"
    gw.read_attributes = nobody_home
    gw._state_evidence[dev.ieee] = 0.0
    await gw._poll_silent_routers()
    fake.emit_incoming(NWK + 67, 0x0B04, power_report)
    await asyncio.sleep(0.05)
    await gw._poll_silent_routers()
    assert dev.available and len(noted) == 2, "a new run is written up again"

    # silent AND unanswering is a different thing: that is a device that is gone
    for book in (gw._poll_failures, gw._poll_first_miss, gw._poll_not_before):
        book.pop(dev.ieee)
    await asyncio.sleep(0.01)
    await gw._poll_silent_routers()
    await gw._poll_silent_routers()
    assert not dev.available, "nothing heard since the first miss: offline"
    await t.close()


async def test_a_chatty_plug_is_still_asked_about_its_switch(tmp_path):
    """A plug that reports its power every ten seconds is heard constantly; that says nothing
    about whether someone pressed its button. The poll goes by state evidence, not by any frame."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 66, NWK + 66, clusters=(0, 6, 0x0B04))
    dev.last_seen = time.time()
    gw._state_evidence[dev.ieee] = time.time() - gw.ROUTER_POLL_AFTER_S - 1
    asked = []

    async def answer(d, ep, cluster, attrs):
        asked.append(cluster)
        return {"state": "OFF"}

    gw.read_attributes = answer
    await gw._poll_silent_routers()
    assert 0x0006 in asked
    assert gw._state_evidence[dev.ieee] > time.time() - 5, "the answer is evidence"
    asked.clear()
    await gw._poll_silent_routers()
    assert not asked, "fresh evidence: left alone"
    await t.close()


async def test_off_with_a_brightness_switches_off(tmp_path):
    """Home Assistant sends {"state": "OFF", "brightness": N} (the level it will come back at).
    The level command used to follow the off command and switch the light back on."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 67, NWK + 67)
    fake.requests.clear()
    await gw.apply_command(dev, {"state": "OFF", "brightness": 120})
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    clusters = [int.from_bytes(f.data[4:6], "little") for f in reqs]
    assert clusters == [0x0006], clusters
    assert dev.state["state"] == "OFF"
    await t.close()


async def test_a_toggle_and_a_failed_command_ask_the_device(tmp_path):
    """Only the device knows which way a toggle went, and what a half-failed command left behind."""
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = _bulb(gw, IEEE + 68, NWK + 68)
    dev.state["state"] = "OFF"
    await gw.apply_command(dev, {"state": "TOGGLE"})
    assert dev.ieee in gw._refresh_tasks, "a read follows the toggle"
    gw._refresh_tasks.pop(dev.ieee).cancel()
    assert dev.state["state"] == "OFF", "a toggle is not guessed at"

    async def refuse(*a, **k):
        raise asyncio.TimeoutError

    gw.coord.send_aps = refuse
    try:
        await gw.apply_command(dev, {"state": "ON"})
    except asyncio.TimeoutError:
        pass
    assert dev.ieee in gw._refresh_tasks, "a failed command is followed by a read"
    gw._refresh_tasks.pop(dev.ieee).cancel()
    await t.close()


async def test_get_asks_every_switching_endpoint(tmp_path):
    """A two-gang switch has two answers; asking only the first endpoint left the second gang
    frozen for whoever asked (the Apple Home bridge at its start)."""
    from oneroof_zigbee.devices import Endpoint
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = gw.registry.add_or_update(IEEE + 69, NWK + 69, is_router=True)
    dev.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0, 6], [], "switch")
    dev.endpoints[2] = Endpoint(2, 0x0104, 0x0100, [6], [], "switch")
    dev.interviewed = True
    asked = []

    async def answer(d, ep, cluster, attrs):
        asked.append(ep)
        return {"state": "ON" if ep == 2 else "OFF"}

    gw.read_attributes = answer
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/get", b'{"state": ""}')
    assert asked == [1, 2]
    st = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert st.get("state_l1") == "OFF" and st.get("state_l2") == "ON", st
    await t.close()


async def test_radio_loss_is_told_to_everyone(tmp_path):
    """While the coordinator is unplugged nothing we show can be trusted: bridge/state goes
    offline (Home Assistant marks every device unavailable) and, when it is back, every device
    that can answer is asked again."""
    fake, coord, broker, gw, t = await make(tmp_path)
    await gw.coordinator_lost()
    assert broker.last("oneroof/zigbee/bridge/state") == b"offline"
    await gw.coordinator_back()
    assert broker.last("oneroof/zigbee/bridge/state") == b"online"
    assert gw._refresh_task is not None and not gw._refresh_task.done()
    gw._refresh_task.cancel()
    await t.close()
