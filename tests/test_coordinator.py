import asyncio

import pytest

from oneroof_zigbee.security import Audit, JoinGuard, JoinPolicy, JoinPolicyError, NetworkSecrets, parse_install_code
from oneroof_zigbee.znp import Coordinator, Transport
from oneroof_zigbee.znp import commands as c
from oneroof_zigbee.znp.unpi import Frame, FrameType, Subsystem
from oneroof_zigbee.znp.wire import Writer
from tests.fake_znp import FakeZnp

IEEE = 0x00124B00DEADBEEF


async def make(strict=False, policy=None, fake=None):
    fake = fake or FakeZnp()
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    guard = JoinGuard(policy or JoinPolicy(cooldown_seconds=0), Audit(None))
    coord = Coordinator(t, s, guard, guard.audit, strict_install_codes=strict)
    await asyncio.wait_for(coord.start(), 5)
    return fake, coord, t


async def test_forms_network_with_random_secrets_and_closes_join():
    fake, coord, t = await make()
    assert fake.formed
    assert fake.nv[c.NvId.PRECFGKEY] == coord.secrets.network_key
    assert fake.nv[c.NvId.PRECFGKEYS_ENABLE] == b"\x00"
    assert int.from_bytes(fake.nv[c.NvId.PANID], "little") == coord.secrets.pan_id
    assert int.from_bytes(fake.nv[c.NvId.CHANLIST], "little") == 1 << 15
    # last permit-join command at startup must be "close"
    assert fake.permit_durations[-1] == 0
    await t.close()


async def test_runtime_security_applied_every_start():
    fake, coord, t = await make()
    reqs = [(f.subsystem, f.command, f.data) for f in fake.requests]
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.BDB_SET_TC_REQUIRE_KEY_EXCHANGE, b"\x01") in reqs
    # default mode = 0 (use the global default key); a Sonoff ZBDongle-P rejects 1 as a boolean with INVALID_PARAMETER
    key_cmds = [d for ss, cmd, d in reqs if ss is c.Subsystem.APP_CNF and cmd == c.AppCnfCmd.BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY]
    assert key_cmds and key_cmds[-1][0] == c.CentralizedKeyMode.DEFAULT_GLOBAL
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.SET_ALLOWREJOIN_TC_POLICY, b"\x00") in reqs
    await t.close()
    # second start with matching NV must NOT re-form
    fake.requests.clear()
    t2 = Transport(fake.reader, fake.writer, timeout=2.0)
    t2.start()
    coord2 = Coordinator(t2, coord.secrets, coord.guard, coord.audit)
    await asyncio.wait_for(coord2.start(), 5)
    kinds = {(f.subsystem, f.command) for f in fake.requests}
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.BDB_START_COMMISSIONING) not in kinds
    assert (c.Subsystem.ZDO, c.ZdoCmd.STARTUP_FROM_APP) in kinds
    await t2.close()


async def test_strict_mode_replaces_public_link_key_and_requires_install_code():
    fake, coord, t = await make(strict=True)
    reqs = [(f.command, f.data) for f in fake.requests if f.subsystem is c.Subsystem.APP_CNF]
    assert (c.AppCnfCmd.BDB_SET_JOINUSESINSTALLCODE, b"\x01") in reqs
    key_cmd = [d for cmd, d in reqs if cmd == c.AppCnfCmd.BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY][-1]
    assert key_cmd[0] == c.CentralizedKeyMode.INSTALL_CODE and key_cmd[1:] == coord.secrets.tc_install_code and len(key_cmd) == 19
    from oneroof_zigbee.security import crc16
    assert crc16(key_cmd[1:17]) == int.from_bytes(key_cmd[17:19], 'little')
    with pytest.raises(PermissionError):
        await coord.permit_join(60, "test")
    await t.close()


async def test_permit_join_with_install_code_registers_derived_key():
    fake, coord, t = await make(strict=True)
    code = parse_install_code("83FED3407A939723A5C639B26916D505")
    secs = await coord.permit_join(60, "test", ieee=IEEE, install_code=code)
    assert secs == 60
    assert fake.install_codes == [(IEEE, bytes.fromhex("66b6900981e1ee3ca4206b6b861c02bb"))]
    assert fake.permit_durations[-1] == 60
    await t.close()


async def test_permit_join_clamped_to_policy_max():
    fake, coord, t = await make(policy=JoinPolicy(max_seconds=30, cooldown_seconds=0))
    secs = await coord.permit_join(600, "test")
    assert secs == 30 and fake.permit_durations[-1] == 30
    await t.close()


async def test_require_install_code_policy_blocks_open_join():
    fake, coord, t = await make(policy=JoinPolicy(require_install_code=True, cooldown_seconds=0))
    with pytest.raises(JoinPolicyError):
        await coord.permit_join(60, "test")
    await t.close()


async def test_unexpected_join_is_evicted_and_alerted():
    fake, coord, t = await make()
    alerts = []
    coord.audit.subscribe(lambda rec: alerts.append(rec) if rec["level"] == "security" else None)
    joined = []
    coord.on_device_joined(lambda d: joined.append(d) or asyncio.sleep(0))
    fake.emit_announce(IEEE, 0x5678)
    await asyncio.sleep(0.1)
    assert joined == []
    assert any(a["type"] == "unexpected_join" for a in alerts)
    leaves = [f for f in fake.requests if f.command == c.ZdoCmd.MGMT_LEAVE_REQ and f.subsystem is c.Subsystem.ZDO]
    assert leaves and int.from_bytes(leaves[-1].data[2:10], "little") == IEEE
    await t.close()


async def test_expected_join_dispatches_and_interview_works():
    fake, coord, t = await make()
    joined = []

    async def cb(d):
        joined.append(d)

    coord.on_device_joined(cb)
    await coord.permit_join(60, "test")
    fake.emit_announce(IEEE, 0x5678)
    await asyncio.sleep(0.1)
    assert joined and joined[0].ieee == IEEE
    eps = await coord.active_endpoints(0x5678)
    assert eps == [1]
    sd = await coord.simple_descriptor(0x5678, 1)
    assert sd.in_clusters == [0, 6, 8]
    await t.close()


async def test_send_aps_waits_for_confirm_and_dispatches_incoming():
    fake, coord, t = await make()
    got = []

    async def cb(m):
        got.append(m)

    coord.on_aps(cb)
    await coord.send_aps(0x5678, 1, 0x0006, b"\x01\x01\x01")
    fake.emit_incoming(0x5678, 0x0402, b"\x18\x01\x0a\x00\x00\x29\x57\x08")
    await asyncio.sleep(0.05)
    assert got and got[0].cluster == 0x0402 and got[0].payload.endswith(b"\x57\x08")
    await t.close()


async def test_known_device_reannounce_is_rejoin_not_eviction():
    fake, coord, t = await make()
    joined = []

    async def cb(d):
        joined.append(d)

    coord.on_device_joined(cb)
    await coord.permit_join(10, "test")
    fake.emit_announce(IEEE, 0x5678)
    await asyncio.sleep(0.05)
    await coord._force_close_join()
    assert coord.guard.window is None and IEEE in coord.known_ieee
    leaves_before = sum(1 for f in fake.requests if f.subsystem is c.Subsystem.ZDO and f.command == c.ZdoCmd.MGMT_LEAVE_REQ)
    alerts = []
    coord.audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    fake.emit_announce(IEEE, 0x9ABC)  # power-cycled, new short address, window closed
    await asyncio.sleep(0.05)
    leaves_after = sum(1 for f in fake.requests if f.subsystem is c.Subsystem.ZDO and f.command == c.ZdoCmd.MGMT_LEAVE_REQ)
    assert leaves_after == leaves_before, "a paired device must never be evicted on rejoin"
    assert alerts == []
    assert len(joined) == 2 and joined[1].nwk == 0x9ABC
    await t.close()


async def test_policy_denial_does_not_register_install_code():
    fake, coord, t = await make(policy=JoinPolicy(cooldown_seconds=1000))
    code = parse_install_code("83FED3407A939723A5C639B26916D505")
    await coord.permit_join(5, "test", ieee=IEEE, install_code=code)
    await coord._force_close_join()
    fake.install_codes.clear()
    with pytest.raises(JoinPolicyError):
        await coord.permit_join(5, "test", ieee=IEEE + 1, install_code=code)
    assert fake.install_codes == []
    await t.close()


async def test_alert_when_firmware_keeps_a_previous_network():
    """If the radio comes up on a different PAN/channel than the keystore (formation ignored by
    the firmware), a security alert is raised instead of silently running with the old key."""
    fake = FakeZnp()
    # the radio keeps reporting an old network whatever NV says
    orig = fake._handle

    def stubborn(f):
        if f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.EXT_NWK_INFO:
            fake.requests.append(f)
            fake._srsp(f, Writer().u16(0).u8(9).u16(0x1A62).u16(0).u64(0).u64(0).u8(11).bytes())
            return
        orig(f)
    fake._handle = stubborn
    alerts = []
    audit = Audit(None)
    audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    guard = JoinGuard(JoinPolicy(cooldown_seconds=0), audit)
    coord = Coordinator(t, s, guard, audit)
    await asyncio.wait_for(coord.start(), 5)
    m = [a for a in alerts if a["type"] == "network_parameters_mismatch"]
    assert m and m[0]["radio_pan_id"] == "0x1a62" and m[0]["radio_channel"] == 11 and m[0]["keystore_channel"] == 15
    await t.close()


@pytest.mark.parametrize("firmware_keeps_set", [True, False])
async def test_frame_counter_is_verified_after_start(firmware_keeps_set):
    """An imported counter must end up on the coordinator — via the SET command when the firmware
    keeps it, otherwise by writing the key item and restarting the network."""
    import dataclasses
    from oneroof_zigbee.znp.coordinator import FRAME_COUNTER_MARGIN
    fake = FakeZnp()
    fake.ignore_set_frame_counter = not firmware_keeps_set
    fake.refuse_key_item_writes = False  # a firmware that allows the direct write
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), frame_counter=44_000_000)
    guard = JoinGuard(JoinPolicy(cooldown_seconds=0), audit)
    coord = Coordinator(t, s, guard, audit)
    await asyncio.wait_for(coord.start(), 10)
    want = 44_000_000 + FRAME_COUNTER_MARGIN
    assert fake.frame_counter == want, "coordinator really carries the imported counter"
    verified = [e for e in events if e["type"] == "frame_counter_verified"]
    assert verified and verified[-1]["value"] == want
    assert not [e for e in events if e["type"] == "frame_counter_unverified"]
    await t.close()


async def test_formation_restores_trust_centre_seed_and_start_verifies_key():
    import dataclasses
    fake = FakeZnp()
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    seed = bytes(range(16))
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), tclk_seed=seed)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert fake.nv[c.NvId.TCLK_SEED] == seed
    assert "tclk_seed_restored" in [e["type"] for e in events]
    assert not [e for e in events if e["type"] == "network_key_mismatch"]
    await t.close()
    # a radio running another key raises an alert at start
    fake2 = FakeZnp()
    alerts = []
    audit2 = Audit(None)
    audit2.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t2 = Transport(fake2.reader, fake2.writer, timeout=2.0)
    t2.start()
    s2 = NetworkSecrets.generate(channel=15)
    coord2 = Coordinator(t2, s2, JoinGuard(JoinPolicy(cooldown_seconds=0), audit2), audit2)
    await asyncio.wait_for(coord2.start(), 10)
    assert not [a for a in alerts if a["type"] == "network_key_mismatch"]
    fake2.active_key = bytes(16)  # the radio "really" uses a different key now
    fake2.refuse_key_item_writes = False  # a firmware that allows the direct write
    events2 = []
    audit2.subscribe(lambda r: events2.append(r))
    await coord2._verify_active_key()
    assert [a for a in alerts if a["type"] == "network_key_mismatch"]
    assert "network_key_repaired" in [e["type"] for e in events2]
    assert fake2.active_key == s2.network_key, "key items rewritten and the radio restarted on the keystore key"
    assert not [a for a in alerts if a["type"] == "network_key_unrepaired"]
    await t2.close()


async def test_frame_counter_refusal_is_reported_not_fatal():
    """Firmware that neither keeps SET_NWK_FRAME_COUNTER nor allows writing the key item: the
    gateway starts anyway and raises an alert instead of crashing."""
    import dataclasses
    fake = FakeZnp()
    fake.ignore_set_frame_counter = True
    fake.refuse_key_item_writes = True
    fake.has_exnv = False  # and no security material table either: nothing left to try
    alerts = []
    audit = Audit(None)
    audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), frame_counter=44_000_000)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert [a for a in alerts if a["type"] == "frame_counter_unverified"]
    await t.close()


async def test_formation_ends_on_the_keystore_key_on_firmware_that_ignores_precfgkey():
    """Modelled on the real firmware: formation makes up its own key; only a 17-byte key item written
    while the stack is stopped sets it. The formed network must run on the keystore key and
    PRECFGKEYS_ENABLE must be 0 afterwards."""
    fake = FakeZnp()
    audit = Audit(None)
    alerts = []
    audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert fake.active_key == s.network_key
    assert fake.nv[c.NvId.PRECFGKEYS_ENABLE][:1] == b"\x00", "never assume the key after formation"
    assert not [a for a in alerts if a["type"] in ("network_key_mismatch", "network_key_unrepaired")]
    await t.close()


async def test_mismatching_key_is_repaired_with_a_length_exact_item_write():
    fake = FakeZnp()
    audit = Audit(None)
    events = []
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    fake.active_key = bytes(16)  # the radio runs on another key (what a formation with ENABLE=0 produced)
    await coord._verify_active_key()
    types = [e["type"] for e in events]
    assert "network_key_mismatch" in types
    repaired = [e for e in events if e["type"] == "network_key_repaired"]
    assert repaired and repaired[-1]["method"] == "nv" and fake.active_key == s.network_key
    assert "network_key_unrepaired" not in types
    assert sum(1 for f in fake.requests if f.subsystem.name == "APP_CNF" and f.command == c.AppCnfCmd.BDB_START_COMMISSIONING) == 1
    await t.close()


@pytest.mark.parametrize("firmware_keeps_set", [True, False])
async def test_frame_counter_via_security_material_table(firmware_keeps_set):
    """Z-Stack 3.x.0: the counter lives in the security material table; it is read from there and,
    when the SET command is not kept, written there (key items are not writable)."""
    import dataclasses
    from oneroof_zigbee.znp.coordinator import FRAME_COUNTER_MARGIN
    fake = FakeZnp()
    fake.ignore_set_frame_counter = not firmware_keeps_set
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), frame_counter=44_000_000)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    want = 44_000_000 + FRAME_COUNTER_MARGIN
    assert fake.sec_material[0][0] == want
    assert await coord.nwk_frame_counter() == want
    assert [e for e in events if e["type"] == "frame_counter_verified"]
    assert not [e for e in events if e["type"] == "frame_counter_unverified"]
    await t.close()


async def test_neighbour_check_reports_ground_truth(monkeypatch):
    """45 s after start the coordinator's neighbour table is read; routers heard = key works."""
    fake = FakeZnp()
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda d: real_sleep(0 if d >= 45 else d))
    await asyncio.wait_for(coord.start(), 10)
    for _ in range(50):
        await real_sleep(0.02)
        if any(e["type"] == "neighbour_check" for e in events):
            break
    chk = next(e for e in events if e["type"] == "neighbour_check")
    assert chk["neighbours"] == 1 and chk["routers"] == 1 and chk["lqi"] == [180]
    assert not [e for e in events if e["type"] == "no_neighbours_heard"]
    await t.close()


async def test_import_restore_end_to_end_on_hostile_firmware():
    """An imported network (key, counter, seed) ends up on the radio: formation, stopped-state writes,
    counter table, seed — then verified at start and the neighbour check reads real neighbours."""
    import dataclasses
    fake = FakeZnp()
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=11), frame_counter=44_000_000, tclk_seed=bytes(range(16)))
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert fake.active_key == s.network_key, "radio on the imported key"
    assert fake.nv[c.NvId.TCLK_SEED] == s.tclk_seed, "trust-centre seed restored"
    assert fake.sec_material[0][0] >= 44_000_000, "frame counter above the imported one"
    types = [e["type"] for e in events]
    assert "network_formed" in types and "frame_counter_verified" in types
    assert "network_key_mismatch" not in types, "no mismatch after formation: the write during formation took"
    await t.close()


async def test_forwarded_zdo_responses_satisfy_the_waiters():
    """Firmware that only forwards ZDO responses through the message callback: the generic
    envelope is converted to the classic indication and node_descriptor()/bind() complete."""
    fake = FakeZnp()
    fake.requests.clear()
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    audit = Audit(None)
    coord = Coordinator(t, NetworkSecrets.generate(channel=15), JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert any(f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.MSG_CB_REGISTER and f.data == b"\xff\xff" for f in fake.requests), "registered for all ZDO messages"

    async def answer_via_callback(cluster, payload, delay=0.05):
        await asyncio.sleep(delay)
        env = Writer().u16(0x1234).u8(0).u16(cluster).u8(0).u8(7).u16(0).raw(payload).bytes()
        fake.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.MSG_CB_INCOMING, env))

    # Node_Desc_rsp: status 0, nwk 0x1234, then a descriptor (router, manufacturer 0x1037)
    desc = bytes([0x01, 0x40, 0x8E]) + (0x1037).to_bytes(2, "little") + bytes([0x7F]) + (0x0064).to_bytes(2, "little") + bytes(5)
    task = asyncio.create_task(answer_via_callback(0x8002, b"\x00" + (0x1234).to_bytes(2, "little") + desc))
    nd = await coord.node_descriptor(0x1234, timeout=2.0)
    await task
    assert nd.status == 0 and nd.manufacturer_code == 0x1037
    # Bind_rsp: status 0
    task = asyncio.create_task(answer_via_callback(0x8021, b"\x00"))
    assert await coord.bind(0x1234, 0x00158D0000000099, 1, 0x0006, timeout=2.0) == 0
    await task
    await t.close()
